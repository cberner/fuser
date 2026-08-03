//! Flags the kernel sends with an open or create request.
//!
//! These occupy the `open_flags` field of `fuse_open_in` and `fuse_create_in`, which is distinct
//! from the `flags` field holding the `O_*` flags of the `open()` call.

use bitflags::bitflags;

bitflags! {
    /// Flags in the `open_flags` field of `fuse_open_in` and `fuse_create_in`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct OpenInFlags: u32 {
        /// The open truncates the file and the caller lacks `CAP_FSETID`, so the filesystem
        /// must clear suid and sgid. Only sent once `FUSE_HANDLE_KILLPRIV_V2` has been
        /// negotiated
        const FUSE_OPEN_KILL_SUIDGID = 1 << 0;
    }
}
