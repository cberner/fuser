use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;
use nix::fcntl::fcntl;
use tokio::io::unix::AsyncFd;

/// AsyncFD [`std::fs::File`] wrapper that represents the `/dev/fuse` device.
#[derive(Debug)]
pub(crate) struct AsyncDevFuse(pub(crate) AsyncFd<std::fs::File>);

impl AsRawFd for AsyncDevFuse {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.0.get_ref().as_raw_fd()
    }
}

impl AsFd for AsyncDevFuse {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.get_ref().as_fd()
    }
}

impl AsyncDevFuse {
    pub(crate) const PATH: &'static str = "/dev/fuse";

    pub(crate) async fn open() -> tokio::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(Self::PATH)?;

        let async_fd = AsyncFd::new(file)
            .map_err(|e| tokio::io::Error::new(e.kind(), format!("AsyncFd::new: {e}")))?;
        Ok(Self(async_fd))
    }

    /// Creates an [`AsyncFd`] from an existing file.
    pub(crate) fn from_file(file: std::fs::File) -> tokio::io::Result<Self> {
        set_nonblocking(&file)
            .map_err(|e| tokio::io::Error::new(e.kind(), format!("set_nonblocking: {e}")))?;
        let async_fd = AsyncFd::new(file)
            .map_err(|e| tokio::io::Error::new(e.kind(), format!("AsyncFd::new: {e}")))?;
        Ok(Self(async_fd))
    }
}

/// Helper function to set a [`std::fs::File`] descriptor to non-blocking mode. This is required for
/// the FUSE device to work properly with async runtimes.
pub(crate) fn set_nonblocking(file: &std::fs::File) -> tokio::io::Result<()> {
    let flags = fcntl(file, FcntlArg::F_GETFL).map_err(tokio::io::Error::from)?;
    let mut oflags = OFlag::from_bits_retain(flags);
    oflags.insert(OFlag::O_NONBLOCK);
    fcntl(file, FcntlArg::F_SETFL(oflags)).map_err(tokio::io::Error::from)?;
    Ok(())
}
