use std::{fs::File, io, os::unix::prelude::AsRawFd, sync::Arc};
use std::os::fd::FromRawFd;
use libc::{c_int, c_void, size_t};
use crate::reply::ReplySender;

/// The implementation of fuse fd clone.
/// This module is just for avoiding the `missing_docs` of `ioctl_read` macro.
#[allow(missing_docs)] // Raised by `ioctl_read!`
mod _fuse_fd_clone {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

    // use clippy_utilities::Cast;
    use nix::fcntl::{self, FcntlArg, FdFlag, OFlag};
    use nix::ioctl_read;
    use nix::sys::stat::Mode;
    ioctl_read!(fuse_fd_clone_impl, 229, 0, u32);

    /// Clones a FUSE session fd into a FUSE worker fd.
    ///
    /// # Safety
    /// Behavior is undefined if any of the following conditions are violated:
    ///
    /// - `session_fd` must be a valid file descriptor to an open FUSE device.
    #[allow(clippy::unnecessary_safety_comment)]
    pub unsafe fn fuse_fd_clone(session_fd: RawFd) -> nix::Result<RawFd> {
        let devname = "/dev/fuse";
        let cloned_fd = fcntl::open(devname, OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty())?;
        // use `OwnedFd` here is just to release the fd when error occurs
        // SAFETY: the `cloned_fd` is just opened
        let cloned_fd = OwnedFd::from_raw_fd(cloned_fd);

        fcntl::fcntl(cloned_fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

        let mut result_fd: u32 = session_fd.try_into().unwrap();
        // SAFETY: `cloned_fd` is ensured to be valid, and `&mut result_fd` is a valid
        // pointer to a value on stack
        fuse_fd_clone_impl(cloned_fd.as_raw_fd(), &mut result_fd)?;
        Ok(cloned_fd.into_raw_fd()) // use `into_raw_fd` to transfer the
        // ownership of the fd
    }
}

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug)]
pub struct Channel(Arc<File>);

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<File>) -> Self {
        Self(device)
    }

    pub(crate) fn new_worker(session_fd: &c_int) -> (Self, c_int) {
        let fd = unsafe { _fuse_fd_clone::fuse_fd_clone(*session_fd) };

        let fd = match fd {
            Ok(fd) => fd,
            Err(err) => {
                panic!("fuse: failed to clone device fd: {:?}", err);
            }
        };

        let device = unsafe { File::from_raw_fd(fd) };

        (Self(Arc::new(device)), fd)
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
}
