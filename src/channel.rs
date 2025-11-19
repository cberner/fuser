use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::AsRawFd,
    },
    sync::Arc,
};

use libc::{c_int, c_void, c_uint, size_t};

// FUSE_DEV_IOC_CLONE ioctl for cloning the /dev/fuse file descriptor
// This is _IOWR(229, 0, uint32_t)
#[cfg(target_os = "linux")]
const FUSE_DEV_IOC_CLONE: libc::c_ulong = 0xc0048701;

#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;
use crate::reply::ReplySender;

/// A raw communication channel to the FUSE kernel driver
#[derive(Clone, Debug)]
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

    /// Clone the channel file descriptor (Linux only, requires clone_fd support)
    /// This creates a new /dev/fuse file descriptor that shares the same mount
    /// but can be used independently for better multi-threading performance.
    #[cfg(target_os = "linux")]
    pub fn clone_fd(&self) -> io::Result<Self> {
        // Open /dev/fuse
        let clone_fd = unsafe {
            libc::open(
                b"/dev/fuse\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };

        if clone_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Clone the master fd
        let master_fd = self.0.as_raw_fd() as c_uint;
        let result = unsafe {
            libc::ioctl(clone_fd, FUSE_DEV_IOC_CLONE, &master_fd as *const c_uint)
        };

        if result < 0 {
            unsafe { libc::close(clone_fd); }
            return Err(io::Error::last_os_error());
        }

        // Wrap in OwnedFd and then File
        let owned_fd = unsafe { OwnedFd::from_raw_fd(clone_fd) };
        let file = File::from(owned_fd);

        Ok(Channel::new(Arc::new(file)))
    }

    /// Clone the channel file descriptor (non-Linux platforms)
    /// On non-Linux platforms, this just returns a copy of the existing channel
    #[cfg(not(target_os = "linux"))]
    pub fn clone_fd(&self) -> io::Result<Self> {
        // On non-Linux platforms, we can't clone the fd, so we just share it
        Ok(Channel::new(self.0.clone()))
    }
}

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
