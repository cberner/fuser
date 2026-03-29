//! Experimental Asynchronous API for fuser. This is gated behind the "async" feature,
//! and is not yet considered stable. The API may change without a major version bump.

#![allow(unused_variables, unused_mut, clippy::too_many_arguments)]

use std::ffi::OsStr;
use std::path::Path;

use log::warn;
use tokio::io;

use crate::{
    Config, Errno, FileHandle, INodeNo, KernelConfig, LockOwner, OpenFlags, Request, WriteFlags,
    ll::reply_async::{DirectoryResponse, GetAttrResponse, LookupResponse},
    reply_async::{ReadResponse, WriteResponse},
    session_async::AsyncSessionBuilder,
};

/// Async filesystem trait. This is the async version of [`crate::Filesystem`]. It follows a more
/// Rust-idiomatic async API design rather than the C-like, callback-based interface used
/// by [`crate::Filesystem`]. It is not intended to be a thin wrapper over that API.
///
/// Instead of callbacks, this uses a call request -> return result response model, which allows
/// for more straightforward control flow and improved error handling.
///
/// Internally, it operates on an async-aware wrapper ([AsyncFD](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html)) around the FUSE device, enabling
/// better integration and performance with async runtimes.
///
/// For the majority of use cases, users should prefer the [`crate::Filesystem`] API. It is more
/// stable and generally performs better in typical scenarios where the primary bottleneck
/// is the kernel round-trip.
///
/// This API is intended for more IO-bound workloads (e.g. network filesystems), where an
/// async model can improve performance by allowing concurrent request handling and
/// integrating cleanly with other asynchronous systems.
#[async_trait::async_trait]
pub trait AsyncFilesystem: Send + Sync + 'static {
    /// Initialize the filesystem. This is called before the kernel is ready to start sending requests
    /// and to let the filesystem know certain configuration details.
    async fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        Ok(())
    }

    /// Clean up filesystem. This is where you drop any resources allocated during the filesystem's
    /// lifetime that won't be automatically cleaned up.
    fn destroy(&mut self) {}

    /// Look up an entry by name and get its attributes. This is called
    /// by the kernel when it needs to know if a file exists and what its attributes are.
    async fn lookup(
        &self,
        context: &Request,
        parent: INodeNo,
        name: &OsStr,
    ) -> Result<LookupResponse, Errno> {
        warn!(
            "lookup not implemented for parent inode {}, name {:?}",
            parent, name
        );
        Err(Errno::ENOTSUP)
    }

    /// Get the attributes of an entry. This is called by the kernel when it needs to know the attributes of
    /// a file, either by inode number or by file handle (created on [`crate::AsyncFilesystem::open`]).
    async fn getattr(
        &self,
        context: &Request,
        ino: INodeNo,
        file_handle: Option<FileHandle>,
    ) -> Result<GetAttrResponse, Errno> {
        warn!("getattr not implemented for inode {}", ino);
        Err(Errno::ENOTSUP)
    }

    /// Return the data of a file. This is called by the kernel when it needs to read the contents
    /// of a file.
    async fn read(
        &self,
        context: &Request,
        ino: INodeNo,
        file_handle: FileHandle,
        offset: u64,
        size: u32,
        flags: OpenFlags,
        lock: Option<LockOwner>,
    ) -> Result<ReadResponse, Errno> {
        warn!(
            "read not implemented for inode {}, offset {}, size {}",
            ino, offset, size
        );
        Err(Errno::ENOTSUP)
    }

    /// Construct a directory listing response for the given directory inode. This is called by
    /// the kernel when it needs to read the contents of a directory.
    async fn readdir(
        &self,
        context: &Request,
        ino: INodeNo,
        file_handle: FileHandle,
        size: u32,
        offset: u64,
    ) -> Result<DirectoryResponse, Errno> {
        warn!(
            "readdir not implemented for inode {}, offset {}, size {}",
            ino, offset, size
        );
        Err(Errno::ENOTSUP)
    }

    /// Write data.
    ///
    /// Write should return exactly the number of bytes requested except on error. An
    /// exception to this is when the file has been opened in `direct_io` mode, in
    /// which case the return value of the write system call will reflect the return
    /// value of this operation. fh will contain the value set by the open method, or
    /// will be undefined if the open method didn't set any value.
    ///
    /// `write_flags`: will contain `FUSE_WRITE_CACHE`, if this write is from the page cache. If set,
    /// the pid, uid, gid, and fh may not match the value that would have been sent if write cachin
    /// is disabled
    /// flags: these are the file flags, such as `O_SYNC`. Only supported with ABI >= 7.9
    /// `lock_owner`: only supported with ABI >= 7.9
    async fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: WriteFlags,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
    ) -> Result<WriteResponse, Errno> {
        warn!(
            "write not implemented for inode {}, offset {}, size {}",
            ino,
            offset,
            data.len()
        );
        Err(Errno::ENOTSUP)
    }
}

/// Mount the given async filesystem to the given mountpoint. This function will
/// not return until the filesystem is unmounted.
///
/// # Errors
/// Returns an error if the options are incorrect, or if the fuse device can't be mounted,
/// and any final error when the session comes to an end.
pub async fn mount_async<FS: AsyncFilesystem, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &Config,
) -> io::Result<()> {
    let session = AsyncSessionBuilder::new()
        .filesystem(filesystem)
        .mountpoint(mountpoint)
        .options(options.clone())?
        .build()
        .await?;
    session.run().await
}
