//! Experimental Asynchronous API for fuser. This is gated behind the "async" feature,
//! and is not yet considered stable. The API may change without a major version bump.

use std::path::Path;

use tokio::io;

use crate::Config;

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
    /// Clean up filesystem.
    /// Called on filesystem exit.
    fn destroy(&mut self) {}
}

/// Mount the given async filesystem to the given mountpoint. This function will
/// not return until the filesystem is unmounted.
///
/// # Errors
/// Returns an error if the options are incorrect, or if the fuse device can't be mounted,
/// and any final error when the session comes to an end.
async fn mount_async<FS: AsyncFilesystem, P: AsRef<Path>>(
    _filesystem: FS,
    _mountpoint: P,
    _options: &Config,
) -> io::Result<()> {
    // Session::new(filesystem, mountpoint.as_ref(), options).and_then(session::Session::run)
    unimplemented!("")
}
