//! FUSE experimental APIs

#[cfg(feature = "experimental-async")]
pub mod async_fuse;

#[cfg(feature = "experimental-async")]
pub use async_fuse::{AsyncFilesystem, TokioAdapter};
