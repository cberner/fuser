use super::FileDescriptorRawHandle;
use libc::O_NONBLOCK;
use libc::{self, c_int, c_void, size_t};
use log::error;
use std::io;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

#[derive(Debug, Clone)]
pub struct SubChannel {
    fd: Arc<AsyncFd<FileDescriptorRawHandle>>,
}
impl SubChannel {
    pub fn as_raw_fd(&self) -> &FileDescriptorRawHandle {
        self.fd.as_ref().get_ref()
    }

    pub fn new(fd: FileDescriptorRawHandle) -> io::Result<SubChannel> {
        let code = unsafe { libc::fcntl(fd.fd, libc::F_SETFL, O_NONBLOCK) };
        if code == -1 {
            error!(
                "fcntl set file handle to O_NONBLOCK command failed with {}",
                code
            );
            return Err(io::Error::last_os_error());
        }

        Ok(SubChannel {
            fd: Arc::new(AsyncFd::new(fd)?),
        })
    }
    /// Send all data in the slice of slice of bytes in a single write (can block).
    pub async fn send(&self, buffer: &[&[u8]]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;

            match guard.try_io(|inner| {
                let iovecs: Vec<_> = buffer
                    .iter()
                    .map(|d| libc::iovec {
                        iov_base: d.as_ptr() as *mut c_void,
                        iov_len: d.len() as size_t,
                    })
                    .collect();
                let rc = unsafe {
                    libc::writev(inner.get_ref().fd, iovecs.as_ptr(), iovecs.len() as c_int)
                };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub fn close(&self) {
        self.fd.get_ref().close()
    }

    pub async fn do_receive(&self, buffer: &'_ mut [u8]) -> io::Result<Option<usize>> {
        use std::time::Duration;
        use tokio::time::timeout;
        loop {
            if let Ok(guard_result) = timeout(Duration::from_millis(1000), self.fd.readable()).await
            {
                let mut guard = guard_result?;
                match guard.try_io(|inner| super::blocking_receive(inner.get_ref(), buffer)) {
                    Ok(result) => return result,
                    Err(_would_block) => {
                        return Ok(None);
                    }
                }
            } else {
                // some termination states when it comes to fuse in the kernel(umount sometimes..), do not trigger readable.
                // so after a timeout/every so often we need to just try do the read manually.
                match super::blocking_receive(self.fd.get_ref(), buffer) {
                    Ok(r) => return Ok(r),
                    Err(e) => {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}
