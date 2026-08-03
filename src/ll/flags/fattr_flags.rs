//! Flags for setattr operations.

use bitflags::bitflags;

bitflags! {
    /// Flags for setattr operations (fuse_setattr_in.valid bitmask).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct FattrFlags: u32 {
        const FATTR_MODE = 1 << 0;
        const FATTR_UID = 1 << 1;
        const FATTR_GID = 1 << 2;
        const FATTR_SIZE = 1 << 3;
        const FATTR_ATIME = 1 << 4;
        const FATTR_MTIME = 1 << 5;
        const FATTR_FH = 1 << 6;
        const FATTR_ATIME_NOW = 1 << 7;
        const FATTR_MTIME_NOW = 1 << 8;
        const FATTR_LOCKOWNER = 1 << 9;
        const FATTR_CTIME = 1 << 10;
        /// The caller lacks `CAP_FSETID`, so the filesystem must clear suid and sgid.
        /// Only sent once `FUSE_HANDLE_KILLPRIV_V2` has been negotiated
        const FATTR_KILL_SUIDGID = 1 << 11;
        #[cfg(target_os = "macos")]
        const FATTR_CRTIME = 1 << 28;
        #[cfg(target_os = "macos")]
        const FATTR_CHGTIME = 1 << 29;
        #[cfg(target_os = "macos")]
        const FATTR_BKUPTIME = 1 << 30;
        #[cfg(target_os = "macos")]
        const FATTR_FLAGS = 1 << 31;
    }
}
