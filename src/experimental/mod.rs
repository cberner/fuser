//! FUSE experimental APIs

#[cfg(feature = "experimental")]
pub mod async_fuse;

#[cfg(feature = "experimental")]
pub use async_fuse::{AsyncFilesystem, TokioAdapter};
