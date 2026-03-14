#![allow(missing_docs, missing_debug_implementations)]

use log::warn;

use std::ffi::OsStr;
use std::future::Future;
use std::sync::Arc;

use crate::FileHandle;
use crate::Filesystem;
use crate::INodeNo;
use crate::LockOwner;
use crate::OpenFlags;
use crate::ReplyAttr;
use crate::ReplyData;
use crate::ReplyDirectory;
use crate::ReplyEntry;
use crate::Request;
use crate::ll::Errno;

/// Adapter to allow running an [`AsyncFilesystem`] with tokio's runtime.
#[derive(Debug)]
pub struct TokioAdapter<T: AsyncFilesystem> {
    inner: Arc<T>,
    runtime: tokio::runtime::Runtime,
}

impl<T: AsyncFilesystem> TokioAdapter<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
            runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        }
    }

    /// Spawn a future on the runtime for direct passthru of async operations.
    pub fn wrap<F>(
        &self,
        fut: impl Future<Output = F> + Send + 'static,
    ) -> tokio::task::JoinHandle<F>
    where
        F: Send + 'static,
    {
        self.runtime.spawn(fut)
    }
}

/// Helper macro to call an async method on the inner filesystem, this is just a thin wrapper around
/// `self.wrap()`, to reduce boilerplate in the `Filesystem` implementation for `TokioAdapter`.
macro_rules! call_fut {
    ($self:ident, $req:ident, $method:ident ( $($arg:expr),* )) => {{
        let inner = $self.inner.clone();
        let req = $req.clone();
        $self.wrap(async move { inner.$method(&req, $($arg),*).await });
    }};
}

/// Adapter to allow running an [`AsyncFilesystem`] with tokio's runtime. Each method just needs to wrap a
/// cooresponding method on the inner filesystem with `self.wrap()`. This will execute the async method of the inner
/// filesystem on the tokio runtime, and allow you to write your filesystem using async/await.
impl<T: AsyncFilesystem + Send + Sync + 'static> Filesystem for TokioAdapter<T> {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_owned = name.to_owned();
        call_fut!(self, req, lookup(parent, &name_owned, reply));
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        call_fut!(self, req, getattr(ino, fh, reply));
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        call_fut!(
            self,
            req,
            read(ino, fh, offset, size, flags, lock_owner, reply)
        );
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        call_fut!(self, req, readdir(ino, fh, offset, reply));
    }
}

/// Experimental Async API, this allows you to write your filesystem using async/await, This is still very much a work
/// in progress, and may be removed or changed without a major version bump. This can be mapped 1:1 to the sync API,
/// but each method will need to be tested thoroughly as time goes on.
#[async_trait::async_trait]
pub trait AsyncFilesystem: Send + Sync + 'static {
    /// Look up a directory entry by name and get its attributes.
    async fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        warn!("[Not Implemented] lookup(parent: {parent:#x?}, name {name:?})");
        reply.error(Errno::ENOSYS);
    }

    /// Get file attributes.
    async fn getattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        warn!("[Not Implemented] getattr(ino: {ino:#x?}, fh: {fh:#x?})");
        reply.error(Errno::ENOSYS);
    }

    /// Read data.
    /// Read should send exactly the number of bytes requested except on EOF or error,
    /// otherwise the rest of the data will be substituted with zeroes. An exception to
    /// this is when the file has been opened in `direct_io` mode, in which case the
    /// return value of the read system call will reflect the return value of this
    /// operation. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value.
    ///
    /// flags: these are the file flags, such as `O_SYNC`. Only supported with ABI >= 7.9
    /// `lock_owner`: only supported with ABI >= 7.9
    async fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        warn!(
            "[Not Implemented] read(ino: {ino:#x?}, fh: {fh}, offset: {offset}, \
            size: {size}, flags: {flags:#x?}, lock_owner: {lock_owner:?})"
        );
        reply.error(Errno::ENOSYS);
    }

    async fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        warn!("[Not Implemented] readdir(ino: {ino:#x?}, fh: {fh}, offset: {offset})");
        reply.error(Errno::ENOSYS);
    }
}
