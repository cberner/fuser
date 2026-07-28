use std::fmt;

use bitflags::bitflags;

bitflags! {
    /// `renameat2` flags on Linux, `renamex_np` flags on macOS.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RenameFlags: u32 {
        /// Don't overwrite newpath of the rename.
        #[cfg(target_os = "linux")]
        const RENAME_NOREPLACE = libc::RENAME_NOREPLACE;
        /// Atomically exchange oldpath and newpath.
        #[cfg(target_os = "linux")]
        const RENAME_EXCHANGE = libc::RENAME_EXCHANGE;
        /// Overlay/union-specific operation.
        #[cfg(target_os = "linux")]
        const RENAME_WHITEOUT = libc::RENAME_WHITEOUT;
        /// Atomically exchange oldpath and newpath.
        #[cfg(target_os = "macos")]
        const RENAME_SWAP = libc::RENAME_SWAP;
        /// Fail if newpath already exists.
        #[cfg(target_os = "macos")]
        const RENAME_EXCL = libc::RENAME_EXCL;
    }
}

impl fmt::Display for RenameFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.bits(), f)
    }
}
