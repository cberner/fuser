use std::{
    io,
    os::{
        fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::AsRawFd,
    },
    sync::Arc,
};

use crate::dev_fuse::DevFuse;
use crate::passthrough::BackingId;

/// FUSE_DEV_IOC_CLONE ioctl number: _IOR(229, 0, uint32_t)
/// This clones a /dev/fuse file descriptor for multi-threaded reading.
/// See: https://www.kernel.org/doc/Documentation/filesystems/fuse.txt
///
/// Note: The ioctl request type varies by platform (i32 on most Linux, c_ulong on some).
/// Using nix::ioctl_write_ptr! would be cleaner but we keep it simple with raw libc.
#[cfg(target_env = "musl")]
const FUSE_DEV_IOC_CLONE: libc::c_int = 0x8004e500u32 as libc::c_int;
#[cfg(not(target_env = "musl"))]
const FUSE_DEV_IOC_CLONE: libc::c_ulong = 0x8004e500;

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug)]
pub(crate) struct Channel(Arc<DevFuse>);

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<DevFuse>) -> Self {
        Self(device)
    }

    /// Receives data up to the capacity of the given buffer (can block).
    pub(crate) fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        Ok(nix::unistd::read(&self.0, buffer)?)
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub(crate) fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }

    /// Clone the FUSE file descriptor using FUSE_DEV_IOC_CLONE ioctl.
    /// This creates a new fd that can independently read FUSE requests,
    /// enabling multi-threaded request processing.
    ///
    /// The cloned fd shares the same FUSE connection but can be used by
    /// a separate thread to read and process requests in parallel.
    ///
    /// # Safety
    /// The cloned fd is valid for reading FUSE requests but responses
    /// must still be written to the original fd (via ChannelSender).
    ///
    /// # Errors
    /// Returns an error if the ioctl fails (e.g., kernel doesn't support
    /// FUSE_DEV_IOC_CLONE, or /dev/fuse can't be opened).
    pub fn clone_fd(&self) -> io::Result<OwnedFd> {
        // Open a new /dev/fuse fd
        let new_fd = unsafe {
            let fd = libc::open(c"/dev/fuse".as_ptr() as *const libc::c_char, libc::O_RDWR);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            OwnedFd::from_raw_fd(fd)
        };

        // Clone the session onto the new fd using ioctl
        let original_fd = self.0.as_raw_fd() as u32;
        let ret = unsafe {
            libc::ioctl(new_fd.as_raw_fd(), FUSE_DEV_IOC_CLONE, &original_fd as *const u32)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(new_fd)
    }

    /// Create a new Channel from an owned fd.
    /// This is useful for creating reader channels from cloned fds.
    pub fn from_fd(fd: OwnedFd) -> Self {
        Self(Arc::new(fd.into()))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChannelSender(Arc<DevFuse>);

impl ChannelSender {
    pub(crate) fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        let rc = nix::sys::uio::writev(&self.0, bufs)?;
        // writev is atomic, so do not need to check how many bytes are written.
        // libfuse does not do it either
        // https://github.com/libfuse/libfuse/blob/6278995cca991978abd25ebb2c20ebd3fc9e8a13/lib/fuse_lowlevel.c#L267
        debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc);
        Ok(())
    }

    pub(crate) fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        BackingId::create(&self.0, fd)
    }
}
