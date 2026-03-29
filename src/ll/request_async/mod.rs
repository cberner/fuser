//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.

use std::convert::TryFrom;

use log::debug;
use log::error;

use crate::AsyncFilesystem;
use crate::Request;
use crate::channel_async::AsyncChannelSender;
use crate::ll;
use crate::ll::Errno;
use crate::ll::ResponseErrno;
use crate::ll::fuse_abi::fuse_in_header;
use crate::ll::reply::Response;
use crate::session::SessionACL;
use crate::session_async::AsyncSessionEventLoop;

/// Asynchronous request data structure (request from the kernel along with a
/// channel sender clone for sending the reply).
#[derive(Debug)]
pub(crate) struct AsyncRequestWithSender {
    /// Async sender for sending the reply
    ch: AsyncChannelSender,
    /// Request header copied out of the kernel buffer so the request can be moved to a task.
    header: fuse_in_header,
    /// Owned request buffer used to re-parse the operation during dispatch.
    data: Box<[u8]>,
}

impl AsyncRequestWithSender {
    /// Create a new request from the given data.
    pub(crate) fn new(
        ch: AsyncChannelSender,
        data: &[u8],
    ) -> Result<AsyncRequestWithSender, tokio::io::Error> {
        let request = ll::AnyRequest::try_from(data).map_err(|err| {
            error!("Failed to parse request from kernel: {}", err);
            tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, "Failed to parse request")
        })?;

        Ok(Self {
            ch,
            // SAFETY: `fuse_in_header` is a plain FUSE ABI POD struct with no drop glue.
            header: unsafe { std::ptr::read(request.header()) },
            data: data.to_vec().into_boxed_slice(),
        })
    }

    /// Async dispatch request to the given filesystem, takes the return from the filesystem and
    /// sends the reply back to the kernel. This follows a more Rust-idiomatic async API design rather than the C-like,
    /// callback-based interface used in [`crate::Filesystem`].
    pub(crate) async fn dispatch<FS: AsyncFilesystem>(&self, session: &AsyncSessionEventLoop<FS>) {
        debug!(
            "FUSE({}) ino {:#018x} thread={}",
            self.header.unique, self.header.nodeid, session.thread_name
        );

        if let Err(errno) = self.dispatch_req(session).await {
            let response = ResponseErrno(errno);
            self.reply(&response).await.unwrap_or_else(|e| {
                error!(
                    "Failed to send error reply for request {}: {e:?}",
                    self.header.unique
                );
            });
        }
    }

    /// Internal dispatch function that matches on the request operation and calls the corresponding filesystem method,
    /// returning the response to send back to the kernel.
    async fn dispatch_req<FS: AsyncFilesystem>(
        &self,
        session: &AsyncSessionEventLoop<FS>,
    ) -> Result<(), Errno> {
        let request = self.request()?;
        let operation = request.operation().map_err(|_| Errno::ENOSYS)?;
        let req_uid = nix::unistd::Uid::from_raw(self.request_header().uid());
        if (session.allowed == SessionACL::RootAndOwner
            && req_uid != session.session_owner
            && !req_uid.is_root())
            || (session.allowed == SessionACL::Owner && req_uid != session.session_owner)
        {
            match &operation {
                ll::Operation::Init(_)
                | ll::Operation::Destroy(_)
                | ll::Operation::Read(_)
                | ll::Operation::ReadDir(_)
                | ll::Operation::Write(_) => {}
                _ => return Err(Errno::EACCES),
            }
        }

        let Some(filesystem) = &session.filesystem.fs else {
            error!("bug: filesystem must be initialized in dispatch_req");
            return Err(Errno::EIO);
        };

        match operation {
            ll::Operation::Init(_) => {
                error!("Unexpected FUSE_INIT after handshake completed");
                Err(Errno::EIO)
            }
            ll::Operation::Destroy(_) => {
                error!("Unexpected FUSE_DESTROY, session should have been cleaned up");
                Err(Errno::EIO)
            }
            ll::Operation::Lookup(x) => {
                let response = filesystem
                    .lookup(self.request_header(), request.nodeid(), x.name().as_ref())
                    .await?;
                self.reply(&response).await
            }
            ll::Operation::ReadDir(x) => {
                let response = filesystem
                    .readdir(
                        self.request_header(),
                        request.nodeid(),
                        x.file_handle(),
                        x.size(),
                        x.offset(),
                    )
                    .await?;
                self.reply(&response).await
            }
            ll::Operation::GetAttr(x) => {
                let response = filesystem
                    .getattr(self.request_header(), request.nodeid(), x.file_handle())
                    .await?;
                self.reply(&response).await
            }
            ll::Operation::Read(x) => {
                let response = filesystem
                    .read(
                        self.request_header(),
                        request.nodeid(),
                        x.file_handle(),
                        x.offset()?,
                        x.size(),
                        x.flags(),
                        x.lock_owner(),
                    )
                    .await?;
                self.reply(&response).await
            }
            ll::Operation::Write(x) => {
                let response = filesystem
                    .write(
                        self.request_header(),
                        request.nodeid(),
                        x.file_handle(),
                        x.offset()?,
                        x.data(),
                        x.write_flags(),
                        x.flags(),
                        x.lock_owner(),
                    )
                    .await?;
                self.reply(&response).await
            }
            _ => {
                error!("Operation not implemented in the async dispatcher yet");
                Err(Errno::ENOSYS)
            }
        }
    }

    // Reply to the kernel with the given response payload, it should be called at most once per request.
    pub(crate) async fn reply<R: Response + Sync>(&self, response: &R) -> Result<(), Errno> {
        response
            .send_reply(&self.ch, self.request_header().unique())
            .await?;
        Ok(())
    }

    /// Returns a Request reference for this request
    #[inline]
    fn request_header(&self) -> &Request {
        Request::ref_cast(&self.header)
    }

    fn request(&self) -> Result<ll::AnyRequest<'_>, Errno> {
        ll::AnyRequest::try_from(&self.data[..]).map_err(|err| {
            error!("Failed to re-parse owned request buffer: {}", err);
            Errno::EIO
        })
    }
}
