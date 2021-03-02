use libc::{self, c_void, size_t};
use log::error;

use std::os::unix::prelude::AsRawFd;
use std::{
    ops::Deref,
    os::unix::io::RawFd,
    sync::{atomic::AtomicBool, Arc},
};

use std::io;

#[derive(Debug, Clone)]
pub struct ArcSubChannel(pub(crate) Arc<SubChannel>);

impl ArcSubChannel {
    pub fn as_raw_fd(&self) -> &FileDescriptorRawHandle {
        self.0.as_ref().as_raw_fd()
    }
}

impl Deref for ArcSubChannel {
    type Target = SubChannel;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
#[async_trait::async_trait]
impl crate::reply::ReplySender for ArcSubChannel {
    async fn send(&self, data: &[&[u8]]) {
        if let Err(err) = SubChannel::send(self.0.as_ref(), data).await {
            error!("Failed to send FUSE reply: {}", err);
        }
    }
}

/// In the latest version of rust this isn't required since RawFd implements AsRawFD
/// but until pretty recently that didn't work. So including this wrapper is cheap and allows
/// us better compatibility.
#[derive(Debug)]
pub struct FileDescriptorRawHandle {
    pub(in crate) fd: RawFd,
    is_closed: AtomicBool,
}

impl FileDescriptorRawHandle {
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            is_closed: AtomicBool::default(),
        }
    }
    pub fn close(&self) {
        let already_closed = self
            .is_closed
            .swap(true, std::sync::atomic::Ordering::SeqCst);
        if !already_closed {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}
impl Drop for FileDescriptorRawHandle {
    fn drop(&mut self) {
        self.close()
    }
}

impl AsRawFd for FileDescriptorRawHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Receives data up to the capacity of the given buffer (can block).
fn blocking_receive(fd: &FileDescriptorRawHandle, buffer: &mut [u8]) -> io::Result<Option<usize>> {
    let rc = unsafe {
        libc::read(
            fd.fd,
            buffer.as_ptr() as *mut c_void,
            buffer.len() as size_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Some(rc as usize))
    }
}

#[cfg(target_os = "macos")]
pub mod blocking_io;

#[cfg(target_os = "macos")]
pub(crate) use blocking_io::SubChannel;

#[cfg(not(target_os = "macos"))]
pub mod nonblocking_io;

#[cfg(not(target_os = "macos"))]
pub(crate) use nonblocking_io::SubChannel;
