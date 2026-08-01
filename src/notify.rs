#[allow(unused)]
use std::convert::TryInto;
#[allow(unused)]
use std::ffi::OsStr;
use std::io;

use crate::INodeNo;
use crate::channel::ChannelSender;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi::FUSE_EXPIRE_ONLY;
use crate::ll::fuse_abi::fuse_notify_code as notify_code;
use crate::ll::notify::Notification;

/// A handle to a pending `poll()` request.
#[derive(Copy, Clone, Debug)]
pub struct PollHandle(pub u64);

/// A [handle](PollHandle) to a pending `poll()` request coupled with notifier reference.
/// Can be saved and used to notify the kernel when a poll is ready.
#[derive(Clone)]
pub struct PollNotifier {
    handle: PollHandle,
    notifier: Notifier,
}

impl PollNotifier {
    pub(crate) fn new(cs: ChannelSender, kh: PollHandle, kernel_capabilities: InitFlags) -> Self {
        Self {
            handle: kh,
            notifier: Notifier::new(cs, kernel_capabilities),
        }
    }

    /// Handle associated with this poll notifier.
    pub fn handle(&self) -> PollHandle {
        self.handle
    }

    /// Notify the kernel that the associated file handle is ready to be polled.
    /// # Errors
    /// Returns an error if the kernel rejects the notification.
    pub fn notify(self) -> io::Result<()> {
        self.notifier.poll(self.handle)
    }
}

impl std::fmt::Debug for PollNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PollHandle").field(&self.handle).finish()
    }
}

/// A handle by which the application can send notifications to the server
#[derive(Debug, Clone)]
pub struct Notifier {
    sender: ChannelSender,
    /// Everything the kernel advertised during init. Some notifications are only
    /// meaningful on a kernel that supports them, and the kernel reports success
    /// regardless, so they are refused here rather than silently doing something else
    kernel_capabilities: InitFlags,
}

impl Notifier {
    pub(crate) fn new(cs: ChannelSender, kernel_capabilities: InitFlags) -> Self {
        Self {
            sender: cs,
            kernel_capabilities,
        }
    }

    /// Notify poll clients of I/O readiness
    /// # Errors
    /// Returns an error if the kernel rejects the notification.
    pub fn poll(&self, kh: PollHandle) -> io::Result<()> {
        let notif = Notification::new_poll(kh);
        self.send(notify_code::FUSE_POLL, &notif)
    }

    /// Invalidate the kernel cache for a given directory entry
    /// # Errors
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn inval_entry(&self, parent: INodeNo, name: &OsStr) -> io::Result<()> {
        let notif = Notification::new_inval_entry(parent, name, 0).map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_ENTRY, &notif)
    }

    /// Expire the kernel cache for a given directory entry, rather than invalidating it.
    ///
    /// The entry is marked for revalidation on next use instead of being forcibly
    /// detached, so anything mounted beneath it stays mounted. Use this in preference to
    /// [`inval_entry()`](Self::inval_entry) when the entry is merely believed to be stale
    /// rather than known to be gone.
    ///
    /// # Errors
    /// Returns `ENOTSUP` if the kernel did not advertise `InitFlags::FUSE_HAS_EXPIRE_ONLY`.
    /// Such a kernel reads the flag as the padding it used to be and invalidates the entry,
    /// detaching any submounts, while still reporting success, so this refuses to send
    /// rather than quietly doing the destructive thing this call exists to avoid.
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn expire_entry(&self, parent: INodeNo, name: &OsStr) -> io::Result<()> {
        if !self
            .kernel_capabilities
            .contains(InitFlags::FUSE_HAS_EXPIRE_ONLY)
        {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        let notif = Notification::new_inval_entry(parent, name, FUSE_EXPIRE_ONLY)
            .map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_ENTRY, &notif)
    }

    /// Invalidate the kernel cache for a given inode (metadata and
    /// data in the given range)
    /// # Errors
    /// Returns an error if the kernel rejects the notification.
    pub fn inval_inode(&self, ino: INodeNo, offset: i64, len: i64) -> io::Result<()> {
        let notif = Notification::new_inval_inode(ino, offset, len);
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_INODE, &notif)
    }

    /// Update the kernel's cached copy of a given inode's data
    /// # Errors
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn store(&self, ino: INodeNo, offset: u64, data: &[u8]) -> io::Result<()> {
        let notif = Notification::new_store(ino, offset, data).map_err(Self::too_big_err)?;
        // Not strictly an invalidate, but the inode we're operating
        // on may have been evicted anyway, so treat is as such
        self.send_inval(notify_code::FUSE_NOTIFY_STORE, &notif)
    }

    /// Invalidate the kernel cache for a given directory entry and inform
    /// inotify watchers of a file deletion.
    /// # Errors
    /// Returns an error if the notification data is too large.
    /// Returns an error if the kernel rejects the notification.
    pub fn delete(&self, parent: INodeNo, child: INodeNo, name: &OsStr) -> io::Result<()> {
        let notif = Notification::new_delete(parent, child, name).map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_DELETE, &notif)
    }

    #[allow(unused)]
    fn send_inval(&self, code: notify_code, notification: &Notification<'_>) -> io::Result<()> {
        match self.send(code, notification) {
            // ENOENT is harmless for an invalidation (the
            // kernel may have already dropped the cached
            // entry on its own anyway), so ignore it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            x => x,
        }
    }

    fn send(&self, code: notify_code, notification: &Notification<'_>) -> io::Result<()> {
        notification
            .with_iovec(code, |iov| self.sender.send(iov))
            .map_err(Self::too_big_err)?
    }

    /// Create an error for indicating when a notification message
    /// would exceed the capacity that its length descriptor field is
    /// capable of encoding.
    fn too_big_err(tfie: std::num::TryFromIntError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("Data too large: {tfie:?}"))
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::sync::Arc;

    use super::*;
    use crate::channel::Channel;
    use crate::dev_fuse::DevFuse;

    fn notifier(kernel_capabilities: InitFlags) -> Notifier {
        // /dev/null stands in for the FUSE device: the cases below either return before
        // sending, or send a notification whose fate is not what is under test
        let dev = Arc::new(DevFuse(
            File::options().write(true).open("/dev/null").unwrap(),
        ));
        Notifier::new(Channel::new(dev).sender(), kernel_capabilities)
    }

    /// A kernel that never advertised expiring would invalidate the entry and report
    /// success, so the request is refused here instead of being sent.
    #[test]
    fn expire_entry_refused_without_kernel_support() {
        let err = notifier(InitFlags::empty())
            .expire_entry(INodeNo::ROOT, OsStr::new("x"))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTSUP));
    }

    #[test]
    fn expire_entry_sent_with_kernel_support() {
        notifier(InitFlags::FUSE_HAS_EXPIRE_ONLY)
            .expire_entry(INodeNo::ROOT, OsStr::new("x"))
            .unwrap();
    }

    /// Invalidating is unconditional: it does not depend on the expire capability.
    #[test]
    fn inval_entry_needs_no_capability() {
        notifier(InitFlags::empty())
            .inval_entry(INodeNo::ROOT, OsStr::new("x"))
            .unwrap();
    }
}
