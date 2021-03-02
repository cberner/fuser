use super::FileDescriptorRawHandle;
use async_trait::async_trait;
use libc::{self, c_int, c_void, size_t};
use log::error;
use std::{io, sync::Arc, time::Duration};

#[derive(Debug, Clone)]
pub struct SubChannel {
    fd: Arc<FileDescriptorRawHandle>,
}

impl SubChannel {
    pub fn as_raw_fd(&self) -> &FileDescriptorRawHandle {
        &self.fd
    }

    pub fn new(fd: FileDescriptorRawHandle, _max_poll_timeout: Duration) -> io::Result<SubChannel> {
        Ok(SubChannel { fd: Arc::new(fd) })
    }

    /// Send all data in the slice of slice of bytes in a single write (can block).
    pub async fn send(&self, buffer: &[&[u8]]) -> io::Result<()> {
        let iovecs: Vec<_> = buffer
            .iter()
            .map(|d| libc::iovec {
                iov_base: d.as_ptr() as *mut c_void,
                iov_len: d.len() as size_t,
            })
            .collect();
        let rc = unsafe { libc::writev(self.fd.fd, iovecs.as_ptr(), iovecs.len() as c_int) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn close(&self) {
        self.fd.close()
    }

    pub async fn do_receive(&self, buffer: &'_ mut [u8]) -> io::Result<Option<usize>> {
        tokio::task::block_in_place(|| super::blocking_receive(&self.fd, buffer))
    }
}
