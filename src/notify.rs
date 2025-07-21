use std::io;

#[allow(unused)]
use std::{convert::TryInto, ffi::OsStr, ffi::OsString};
use crossbeam_channel::{SendError, Sender};

use crate::{
    channel::ChannelSender,
    // renaming ll::notify::Notificatition to distinguish from crate::Notification
    ll::{fuse_abi::fuse_notify_code as notify_code, notify::Notification as NotificationBuf},
    // What we're sending here aren't really replies, but they
    // move in the same direction (userspace->kernel), so we can
    // reuse ReplySender for it.
    reply::ReplySender,
};

/// Poll event data to be sent to the kernel
#[cfg(feature = "abi-7-11")]
#[derive(Debug, Copy, Clone)]
pub struct Poll {
    /// Poll handle: the unique idenifier from a previous poll request
    pub ph: u64,
    /// Events flag: binary encoded information about resource availability
    pub events: u32
}

/// Invalid entry notification to be sent to the kernel
#[cfg(feature = "abi-7-12")]
#[derive(Debug, Clone)]
pub struct InvalEntry {
    /// Parent: the inode of the parent of the invalid entry
    pub parent: u64,
    /// Name: the file name of the invalid entry
    pub name: OsString
}

/// Invalid inode notification to be sent to the kernel
#[cfg(feature = "abi-7-12")]
#[derive(Debug, Copy, Clone)]
pub struct InvalInode {
    /// Inode with invalid metadata
    pub ino: u64,
    /// Start of invalid metadata
    pub offset: i64,
    /// Length of invalid metadata
    pub len: i64
}

/// Store inode notification to be sent to the kernel
#[cfg(feature = "abi-7-15")]
#[derive(Debug, Clone)]
pub struct Store {
    /// ino: the inode to be updated
    pub ino: u64,
    /// The start location of the metadata to be updated
    pub offset: u64,
    /// The new metadata
    pub data: Vec<u8>
}

/// Deleted file notification to be sent to the kernel
#[cfg(feature = "abi-7-18")]
#[derive(Debug, Clone)]
pub struct Delete {
    /// Parent: the inode of the parent directory that contained the deleted entry
    pub parent: u64,
    /// ino: the inode of the deleted file
    pub ino: u64,
    /// Name: the file name of the deleted entry
    pub name: OsString
}

/// The list of supported notification types
#[derive(Debug)]
pub enum Notification {
    /// A poll event notification
    #[cfg(feature = "abi-7-11")]
    Poll((Poll, Option<Sender<io::Result<()>>>)),
    /// An invalid entry notification
    #[cfg(feature = "abi-7-12")]
    InvalEntry((InvalEntry, Option<Sender<io::Result<()>>>)),
    /// An invalid inode notification
    #[cfg(feature = "abi-7-12")]
    InvalInode((InvalInode, Option<Sender<io::Result<()>>>)),
    /// An inode metadata update notification
    #[cfg(feature = "abi-7-15")]
    Store((Store, Option<Sender<io::Result<()>>>)),
    /// An inode deletion notification
    #[cfg(feature = "abi-7-18")]
    Delete((Delete, Option<Sender<io::Result<()>>>)),
    /// (Internal) Disable notifications for this session
    Stop
}

#[cfg(feature = "abi-7-11")]
impl From<Poll>       for Notification {fn from(notification: Poll)       -> Self{Notification::Poll((notification, None))}}
#[cfg(feature = "abi-7-12")]
impl From<InvalEntry> for Notification {fn from(notification: InvalEntry) -> Self{Notification::InvalEntry((notification, None))}}
#[cfg(feature = "abi-7-12")]
impl From<InvalInode> for Notification {fn from(notification: InvalInode) -> Self{Notification::InvalInode((notification, None))}}
#[cfg(feature = "abi-7-15")]
impl From<Store>      for Notification {fn from(notification: Store)      -> Self{Notification::Store((notification, None))}}
#[cfg(feature = "abi-7-18")]
impl From<Delete>     for Notification {fn from(notification: Delete)     -> Self{Notification::Delete((notification, None))}}

/// A handle by which the application can send notifications to the server
#[derive(Debug, Clone)]
pub(crate) struct Notifier(ChannelSender);

impl Notifier {
    pub(crate) fn new(cs: ChannelSender) -> Self {
        Self(cs)
    }

    pub(crate) fn notify(&self, notification: Notification) -> io::Result<()> {
        // These branches follow a pattern:
        // 1: Attempt to deliver the notification to the Kernel.
        // 2: Attempt to deliver the result of 1 to the Filesystem.
        // 3: Return something to the Session.
        // - If the result of 1 was delivered to the Filesystem,
        //   then `Ok` returns to Session loop.
        //   the Filesystem is expected to handle the error, if any.
        // - If the result of 1 could not be delivered to the filesystem,
        //   then the result of 1 (but just the error part) is returned to Session.
        //   The ok value, if any, is discarded using the trivial closure `|_|{}`
        match notification {
            #[cfg(feature = "abi-7-11")]
            Notification::Poll((data, sender)) => {
                let res = self.poll(data);
                if let Some(sender) = sender {
                    if let Err(SendError(res)) = sender.send(res) {
                        log::warn!("Poll notification reply {res:?} could not be delivered.");
                        return res;
                    }
                    return Ok(());
                }
                res
            },
            #[cfg(feature = "abi-7-12")]
            Notification::InvalEntry((data, sender)) => {
                let res = self.inval_entry(data);
                if let Some(sender) = sender {
                    if let Err(SendError(res)) = sender.send(res) {
                        log::warn!("InvalEntry notification reply {res:?} could not be delivered.");
                        return res;
                    }
                    return Ok(());
                }
                res
            },
            #[cfg(feature = "abi-7-12")]
            Notification::InvalInode((data, sender)) => {
                let res = self.inval_inode(data);
                if let Some(sender) = sender {
                    if let Err(SendError(res)) = sender.send(res) {
                        log::warn!("InvalInode notification reply {res:?} could not be delivered.");
                        return res;
                    }
                    return Ok(());
                }
                res
            },
            #[cfg(feature = "abi-7-15")]
            Notification::Store((data, sender)) => {
                let res = self.store(data);
                if let Some(sender) = sender {
                    if let Err(SendError(res)) = sender.send(res) {
                        log::warn!("Store notification reply {res:?} could not be delivered.");
                        return res;
                    }
                    return Ok(());
                }
                res
            },
            #[cfg(feature = "abi-7-18")]
            Notification::Delete((data, sender)) => {
                let res = self.delete(data);
                if let Some(sender) = sender {
                    if let Err(SendError(res)) = sender.send(res) {
                        log::warn!("Delete notification reply {res:?} could not be delivered.");
                        return res;
                    }
                    return Ok(());
                }
                res
            },
            // For completeness
            Notification::Stop => Ok(())
        }
    }

    /// Notify poll clients of I/O readiness
    #[cfg(feature = "abi-7-11")]
    pub fn poll(&self, notification: Poll) -> io::Result<()> {
        let notif = NotificationBuf::new_poll(notification.ph);
        self.send(notify_code::FUSE_POLL, &notif)
    }

    /// Invalidate the kernel cache for a given directory entry
    #[cfg(feature = "abi-7-12")]
    pub fn inval_entry(&self, notification: InvalEntry) -> io::Result<()> {
        let notif = NotificationBuf::new_inval_entry(notification.parent, notification.name.as_ref()).map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_ENTRY, &notif)
    }

    /// Invalidate the kernel cache for a given inode (metadata and
    /// data in the given range)
    #[cfg(feature = "abi-7-12")]
    pub fn inval_inode(&self, notification: InvalInode ) -> io::Result<()> {
        let notif = NotificationBuf::new_inval_inode(notification.ino, notification.offset, notification.len);
        self.send_inval(notify_code::FUSE_NOTIFY_INVAL_INODE, &notif)
    }

    /// Update the kernel's cached copy of a given inode's data
    #[cfg(feature = "abi-7-15")]
    pub fn store(&self, notification: Store) -> io::Result<()> {
        let notif = NotificationBuf::new_store(notification.ino, notification.offset, &notification.data).map_err(Self::too_big_err)?;
        // Not strictly an invalidate, but the inode we're operating
        // on may have been evicted anyway, so treat is as such
        self.send_inval(notify_code::FUSE_NOTIFY_STORE, &notif)
    }

    /// Invalidate the kernel cache for a given directory entry and inform
    /// inotify watchers of a file deletion.
    #[cfg(feature = "abi-7-18")]
    pub fn delete(&self, notification: Delete) -> io::Result<()> {
        let notif = NotificationBuf::new_delete(notification.parent, notification.ino, &notification.name).map_err(Self::too_big_err)?;
        self.send_inval(notify_code::FUSE_NOTIFY_DELETE, &notif)
    }

    #[cfg(feature = "abi-7-12")]
    fn send_inval(&self, code: notify_code, notification: &NotificationBuf<'_>) -> io::Result<()> {
        match self.send(code, notification) {
            // ENOENT is harmless for an invalidation (the
            // kernel may have already dropped the cached
            // entry on its own anyway), so ignore it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            x => x,
        }
    }

    fn send(&self, code: notify_code, notification: &NotificationBuf<'_>) -> io::Result<()> {
        notification
            .with_iovec(code, |iov| self.0.send(iov))
            .map_err(Self::too_big_err)?
    }

    /// Create an error for indicating when a notification message
    /// would exceed the capacity that its length descriptor field is
    /// capable of encoding.
    fn too_big_err(tfie: std::num::TryFromIntError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("Data too large: {tfie}"))
    }
}
