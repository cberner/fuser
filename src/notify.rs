#[allow(unused)]
use std::convert::TryInto;
#[allow(unused)]
use std::ffi::OsStr;
use std::io;

use crate::INodeNo;
use crate::Version;
use crate::channel::ChannelSender;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi::FUSE_EXPIRE_ONLY;
use crate::ll::fuse_abi::FUSE_KERNEL_MINOR_VERSION;
use crate::ll::fuse_abi::FUSE_KERNEL_VERSION;
use crate::ll::fuse_abi::FUSE_NOTIFY_INC_EPOCH_VERSION;
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
    pub(crate) fn new(
        cs: ChannelSender,
        kh: PollHandle,
        kernel_capabilities: InitFlags,
        kernel_abi: Option<Version>,
    ) -> Self {
        Self {
            handle: kh,
            notifier: Notifier::new(cs, kernel_capabilities, kernel_abi),
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
    /// The ABI version the kernel offered during init, or `None` before init has run.
    /// Notifications added after a given version have no capability bit to key on, so the
    /// version is what says whether the kernel will understand them. This is what the kernel
    /// advertised, not what the connection settled on: see [`Notifier::negotiated_abi`]
    kernel_abi: Option<Version>,
}

impl Notifier {
    pub(crate) fn new(
        cs: ChannelSender,
        kernel_capabilities: InitFlags,
        kernel_abi: Option<Version>,
    ) -> Self {
        Self {
            sender: cs,
            kernel_capabilities,
            kernel_abi,
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

    /// Invalidate every cached directory entry at once, by incrementing the connection's
    /// epoch.
    ///
    /// The kernel stamps each dentry with the epoch current when it was looked up, and
    /// treats one stamped with an older epoch as stale. Incrementing therefore invalidates
    /// the whole dentry and readdir cache in constant time, where
    /// [`inval_entry()`](Self::inval_entry) costs a notification per entry and needs the
    /// filesystem to know the names to begin with. That suits a backing store that has
    /// changed wholesale, or one whose changes cannot be enumerated.
    ///
    /// Invalidation is lazy, as with [`expire_entry()`](Self::expire_entry): entries are
    /// revalidated on next use rather than forcibly detached, so anything mounted beneath
    /// one stays mounted. A kernel configured with the `inval_wq` module parameter also
    /// prunes unused entries in the background.
    ///
    /// # Errors
    /// Returns `ENOTSUP` if the connection settled on an ABI older than 7.44, which has no
    /// case for this notification. Such a kernel does reject it, unlike the one
    /// [`expire_entry()`](Self::expire_entry) guards against, but only with an `EINVAL`
    /// that says nothing about why, and a caller holding a `Notifier` has no way to check
    /// the version for itself.
    /// Returns an error if the kernel rejects the notification.
    pub fn inc_epoch(&self) -> io::Result<()> {
        // None before init has run, which is also a connection nothing can be sent on yet
        if self
            .negotiated_abi()
            .is_none_or(|v| v < FUSE_NOTIFY_INC_EPOCH_VERSION)
        {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        let notif = Notification::new_inc_epoch();
        self.send(notify_code::FUSE_NOTIFY_INC_EPOCH, &notif)
    }

    /// What the connection actually speaks: the lower of what the kernel offered during init
    /// and what this crate replied with.
    ///
    /// Both halves matter. The kernel dispatches a notification on its code alone, without
    /// consulting the version, so what it offered is what decides whether it has a case for
    /// one at all. But it records the replied version verbatim as the connection's, so
    /// sending something newer than that is out of protocol however tolerant the dispatch
    /// happens to be. Taking the lower keeps to both.
    fn negotiated_abi(&self) -> Option<Version> {
        self.kernel_abi.map(|kernel| {
            Version(
                kernel.0.min(FUSE_KERNEL_VERSION),
                kernel.1.min(FUSE_KERNEL_MINOR_VERSION),
            )
        })
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
        notifier_with_abi(kernel_capabilities, Some(FUSE_NOTIFY_INC_EPOCH_VERSION))
    }

    fn notifier_with_abi(kernel_capabilities: InitFlags, kernel_abi: Option<Version>) -> Notifier {
        // /dev/null stands in for the FUSE device: the cases below either return before
        // sending, or send a notification whose fate is not what is under test
        let dev = Arc::new(DevFuse(
            File::options().write(true).open("/dev/null").unwrap(),
        ));
        Notifier::new(Channel::new(dev).sender(), kernel_capabilities, kernel_abi)
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

    /// Incrementing the epoch keys on the ABI version rather than a capability, since the
    /// kernel advertises no bit for it.
    #[test]
    fn inc_epoch_refused_below_its_abi_version() {
        for abi in [None, Some(Version(7, 43)), Some(Version(7, 6))] {
            let err = notifier_with_abi(InitFlags::all(), abi)
                .inc_epoch()
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::ENOTSUP), "{abi:?}");
        }
    }

    /// Both sides have to reach 7.44, so what this crate replies with decides it just as much
    /// as what the kernel offers. On macOS that is 7.19 and never enough, which is the answer
    /// there however new the kernel is.
    #[test]
    fn inc_epoch_sent_only_when_this_crate_reports_its_abi_version() {
        let reported = Version(FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);
        let this_crate_reaches_it = reported >= FUSE_NOTIFY_INC_EPOCH_VERSION;
        for abi in [Version(7, 44), Version(7, 45), Version(7, 99)] {
            let sent = notifier_with_abi(InitFlags::empty(), Some(abi))
                .inc_epoch()
                .is_ok();
            assert_eq!(sent, this_crate_reaches_it, "{abi:?}");
        }
    }

    /// A kernel offering more than this crate replies with does not make the extra versions
    /// part of the connection, since the kernel records the reply as its own.
    #[test]
    fn negotiated_abi_is_capped_by_what_this_crate_replies_with() {
        let notifier = notifier_with_abi(InitFlags::empty(), Some(Version(7, 99)));
        assert_eq!(
            notifier.negotiated_abi(),
            Some(Version(FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION))
        );
        // ...and a kernel offering less caps it the other way round. 7.8 is below what every
        // platform replies with, macOS included, so this does not depend on which one it is
        let notifier = notifier_with_abi(InitFlags::empty(), Some(Version(7, 8)));
        assert_eq!(notifier.negotiated_abi(), Some(Version(7, 8)));
    }
}
