use std::io;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::sync::Arc;

use nix::errno::Errno;

use crate::dev_fuse::DevFuse;
use crate::passthrough::BackingId;

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug, Clone)]
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
    fn receive(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        #[cfg(fuser_macfuse_fskit)]
        if let Some(channel) = &self.0.mf_channel {
            return channel.receive(buffer);
        }
        nix::unistd::read(&self.0, buffer)
    }

    /// Receives data up to the capacity of the given buffer (can block),
    /// retrying on errors that are safe to retry (ENOENT, EINTR, EAGAIN).
    ///
    /// - ENOENT: Operation interrupted. According to FUSE, this is safe to retry.
    /// - EINTR: Interrupted system call, retry.
    /// - EAGAIN: Explicitly instructed to try again.
    pub(crate) fn receive_retrying(&self, buffer: &mut [u8]) -> nix::Result<usize> {
        loop {
            match self.receive(buffer) {
                Ok(size) => return Ok(size),
                Err(Errno::ENOENT | Errno::EINTR | Errno::EAGAIN) => continue,
                Err(err) => return Err(err),
            }
        }
    }

    /// Returns the FUSE device of this channel.
    pub(crate) fn device(&self) -> Arc<DevFuse> {
        self.0.clone()
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub(crate) fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }

    /// Clone the FUSE device fd using FUSE_DEV_IOC_CLONE ioctl.
    ///
    /// This creates a new fd that can read FUSE requests independently,
    /// enabling true parallel request processing. The kernel distributes
    /// requests across all cloned fds.
    ///
    /// Requires Linux 4.5+. Returns an error on older kernels or non-Linux.
    #[cfg(target_os = "linux")]
    pub(crate) fn clone_fd(&self) -> io::Result<Channel> {
        use std::os::fd::AsRawFd;

        let new_dev = DevFuse::open()?;

        let mut source_fd = self.0.as_raw_fd() as u32;
        // SAFETY: fuse_dev_ioc_clone is a valid ioctl for /dev/fuse
        unsafe {
            crate::ll::ioctl::fuse_dev_ioc_clone(new_dev.as_raw_fd(), &mut source_fd)?;
        }

        Ok(Channel::new(Arc::new(new_dev)))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChannelSender(Arc<DevFuse>);

impl ChannelSender {
    pub(crate) fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        #[cfg(fuser_macfuse_fskit)]
        if let Some(channel) = &self.0.mf_channel {
            channel.send(bufs)?;
            return Ok(());
        }
        #[cfg(not(target_os = "netbsd"))]
        let rc = nix::sys::uio::writev(&self.0, bufs)?;
        #[cfg(target_os = "netbsd")]
        let rc = retry_on_emsgsize(bufs, || nix::sys::uio::writev(&self.0, bufs))?;
        // writev is atomic, so do not need to check how many bytes are written.
        // libfuse does not do it either
        // https://github.com/libfuse/libfuse/blob/6278995cca991978abd25ebb2c20ebd3fc9e8a13/lib/fuse_lowlevel.c#L267
        debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc);
        Ok(())
    }

    pub(crate) fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        BackingId::create(&self.0, fd)
    }

    pub(crate) unsafe fn wrap_backing(&self, id: u32) -> BackingId {
        unsafe { BackingId::wrap_raw(&self.0, id) }
    }
}

/// On NetBSD the device is a `SOCK_SEQPACKET` socket to perfused. A send there fails with
/// `EMSGSIZE`, rather than blocking, while perfused has not read enough of the earlier replies
/// for this one to fit, and `poll(2)` reports the socket writable all the same. Dropping the
/// reply would hang its caller forever, so retry after a short sleep, as perfused does for its
/// own writes.
#[cfg(any(target_os = "netbsd", test))]
fn retry_on_emsgsize(
    bufs: &[io::IoSlice<'_>],
    mut write: impl FnMut() -> nix::Result<usize>,
) -> nix::Result<usize> {
    let mut retries: u32 = 0;
    loop {
        match write() {
            Err(Errno::EMSGSIZE) => {
                retries += 1;
                if retries == 1000 {
                    log::warn!(
                        "FUSE reply of {} bytes still does not fit in perfused's socket buffer \
                         after {retries} tries; retrying",
                        bufs.iter().map(|b| b.len()).sum::<usize>()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::IoSlice;

    use nix::errno::Errno;

    use super::retry_on_emsgsize;

    #[test]
    fn emsgsize_is_retried_until_the_reply_fits() {
        let bufs = [IoSlice::new(b"reply")];
        let mut calls = 0;
        let result = retry_on_emsgsize(&bufs, || {
            calls += 1;
            if calls <= 3 {
                Err(Errno::EMSGSIZE)
            } else {
                Ok(5)
            }
        });
        assert_eq!(result, Ok(5));
        assert_eq!(calls, 4);
    }

    #[test]
    fn other_errors_are_not_retried() {
        let bufs = [IoSlice::new(b"reply")];
        let mut calls = 0;
        let result = retry_on_emsgsize(&bufs, || {
            calls += 1;
            Err(Errno::ENOENT)
        });
        assert_eq!(result, Err(Errno::ENOENT));
        assert_eq!(calls, 1);
    }
}
