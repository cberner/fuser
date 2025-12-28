use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::AsRawFd,
    },
    sync::Arc,
};

use libc::{c_int, c_void, size_t};

#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;
use crate::reply::ReplySender;

/// FUSE_DEV_IOC_CLONE ioctl number for cloning /dev/fuse file descriptors.
///
/// Calculated as `_IOR(229, 0, uint32_t)` = `0x80000000 | (4 << 16) | (229 << 8) | 0`
/// See: https://www.kernel.org/doc/Documentation/filesystems/fuse.txt
#[cfg(all(target_os = "linux", target_env = "musl"))]
const FUSE_DEV_IOC_CLONE: libc::c_int = 0x8004e500u32 as libc::c_int;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
const FUSE_DEV_IOC_CLONE: libc::c_ulong = 0x8004e500;

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug)]
pub struct Channel(Arc<File>);

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<File>) -> Self {
        Self(device)
    }

    /// Receives data up to the capacity of the given buffer (can block).
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let rc = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                buffer.as_ptr() as *mut c_void,
                buffer.len() as size_t,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }

    /// Clone the FUSE file descriptor using `FUSE_DEV_IOC_CLONE` ioctl.
    ///
    /// Creates a new fd that can independently read FUSE requests, enabling
    /// multi-threaded request processing. The cloned fd shares the same FUSE
    /// connection but can be used by a separate thread to read requests in parallel.
    ///
    /// # Platform Support
    /// This is only available on Linux. On other platforms, this method is not compiled.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `/dev/fuse` cannot be opened
    /// - The `FUSE_DEV_IOC_CLONE` ioctl fails (e.g., kernel doesn't support it)
    #[cfg(target_os = "linux")]
    pub fn clone_fd(&self) -> io::Result<OwnedFd> {
        // Open a new /dev/fuse fd
        let fd = unsafe { libc::open(c"/dev/fuse".as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is valid, we just opened it successfully
        let new_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Clone the session onto the new fd
        let original_fd = self.0.as_raw_fd() as u32;
        // SAFETY: ioctl with FUSE_DEV_IOC_CLONE expects a pointer to u32 containing the source fd
        let ret = unsafe { libc::ioctl(new_fd.as_raw_fd(), FUSE_DEV_IOC_CLONE, &original_fd) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(new_fd)
    }
}

/// Sender for FUSE replies over a channel
#[derive(Clone, Debug)]
pub struct ChannelSender(Arc<File>);

impl ReplySender for ChannelSender {
    fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        let rc = unsafe {
            libc::writev(
                self.0.as_raw_fd(),
                bufs.as_ptr() as *const libc::iovec,
                bufs.len() as c_int,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc as usize);
            Ok(())
        }
    }

    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        BackingId::create(&self.0, fd)
    }
}
