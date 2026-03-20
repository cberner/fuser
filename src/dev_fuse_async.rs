use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
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

        let async_fd = AsyncFd::new(file)?;
        Ok(Self(async_fd))
    }

    /// Creates an [`AsyncFd`] from an existing file.
    pub(crate) fn from_file(file: std::fs::File) -> tokio::io::Result<Self> {
        let async_fd = AsyncFd::new(file)?;
        Ok(Self(async_fd))
    }
}
