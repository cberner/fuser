use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::Weak;

use log::error;

use crate::dev_fuse::DevFuse;
use crate::ll::ioctl::fuse_backing_map;
use crate::ll::ioctl::fuse_dev_ioc_backing_close;
use crate::ll::ioctl::fuse_dev_ioc_backing_open;

/// A reference to a previously opened fd intended to be used for passthrough
///
/// You can create these via [`ReplyOpen::open_backing()`](crate::ReplyOpen::open_backing)
/// and send them via [`ReplyOpen::opened_passthrough()`](crate::ReplyOpen::opened_passthrough).
///
/// When working with backing IDs you need to ensure that they live "long enough".  A good practice
/// is to create them in the [`Filesystem::open()`](crate::Filesystem::open) impl,
/// store them in the struct of your Filesystem impl, then drop them in the
/// [`Filesystem::release()`](crate::Filesystem::release) impl. Dropping them immediately after
/// sending them in the `Filesystem::open()` impl can lead to the kernel returning EIO when userspace
/// attempts to access the file.
///
/// This is implemented as a safe wrapper around the `backing_id` field of the `fuse_backing_map`
/// struct used by the ioctls involved in fd passthrough.  It is created by performing a
/// `FUSE_DEV_IOC_BACKING_OPEN` ioctl on an fd and has a Drop trait impl which makes a matching
/// `FUSE_DEV_IOC_BACKING_CLOSE` call.  It holds a weak reference on the fuse channel to allow it to
/// make that call (if the channel hasn't already been closed).
#[derive(Debug)]
pub struct BackingId {
    pub(crate) channel: Weak<DevFuse>,
    /// The `backing_id` field passed to and from the kernel
    pub(crate) backing_id: u32,
}

impl BackingId {
    /// Creates a new backing file reference for the given file descriptor.
    ///
    /// Usually, you will want to use [`ReplyOpen::open_backing()`](crate::ReplyOpen::open_backing)
    /// instead, since this method will return a raw `backing_id` value instead of a managed
    /// `BackingId` wrapper. As such you must manage the lifetime of the backing file yourself.
    ///
    /// This method is useful if you want to open a backing file reference without access to a reply
    /// object.
    pub fn create_raw(fuse_dev: impl AsFd, fd: impl AsFd) -> std::io::Result<u32> {
        if !cfg!(target_os = "linux") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "backing IDs are only supported on Linux",
            ));
        }

        let map = fuse_backing_map {
            fd: fd.as_fd().as_raw_fd() as u32,
            flags: 0,
            padding: 0,
        };
        let id = unsafe { fuse_dev_ioc_backing_open(fuse_dev.as_fd().as_raw_fd(), &map) }?;

        Ok(id as u32)
    }

    pub(crate) fn create(channel: &Arc<DevFuse>, fd: impl AsFd) -> std::io::Result<Self> {
        Ok(Self {
            channel: Arc::downgrade(channel),
            backing_id: Self::create_raw(channel, fd)?,
        })
    }

    pub(crate) unsafe fn wrap_raw(channel: &Arc<DevFuse>, id: u32) -> Self {
        Self {
            channel: Arc::downgrade(channel),
            backing_id: id,
        }
    }

    /// Converts this backing file reference into the raw `backing_id` value as returned by the kernel.
    ///
    /// This method transfers ownership of the backing file to the caller, who must invoke the
    /// `FUSE_DEV_IOC_BACKING_CLOSE` themselves once they wish to close the backing file.
    ///
    /// The returned ID may subsequently be reopened using
    /// [`ReplyOpen::wrap_backing()`](crate::ReplyOpen::wrap_backing).
    pub fn into_raw(mut self) -> u32 {
        let id = self.backing_id;
        drop(std::mem::take(&mut self.channel));
        std::mem::forget(self);
        id
    }
}

impl Drop for BackingId {
    fn drop(&mut self) {
        if let Some(ch) = self.channel.upgrade() {
            if let Err(e) = unsafe { fuse_dev_ioc_backing_close(ch.as_raw_fd(), &self.backing_id) }
            {
                error!("Failed to close backing fd: {e}");
            }
        }
    }
}
