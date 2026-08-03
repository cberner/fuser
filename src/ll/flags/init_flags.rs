//! Init request/reply flags.

use bitflags::bitflags;

bitflags! {
    /// Init request/reply flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct InitFlags: u64 {
        /// asynchronous read requests
        const FUSE_ASYNC_READ = 1 << 0;
        /// remote locking for POSIX file locks
        const FUSE_POSIX_LOCKS = 1 << 1;
        /// kernel sends file handle for fstat, etc...
        const FUSE_FILE_OPS = 1 << 2;
        /// handles the O_TRUNC open flag in the filesystem
        const FUSE_ATOMIC_O_TRUNC = 1 << 3;
        /// filesystem handles lookups of "." and ".."
        const FUSE_EXPORT_SUPPORT = 1 << 4;
        /// filesystem can handle write size larger than 4kB
        const FUSE_BIG_WRITES = 1 << 5;
        /// don't apply umask to file mode on create operations
        const FUSE_DONT_MASK = 1 << 6;
        /// kernel supports splice write on the device
        const FUSE_SPLICE_WRITE = 1 << 7;
        /// kernel supports splice move on the device
        const FUSE_SPLICE_MOVE = 1 << 8;
        /// kernel supports splice read on the device
        const FUSE_SPLICE_READ = 1 << 9;
        /// remote locking for BSD style file locks
        const FUSE_FLOCK_LOCKS = 1 << 10;
        /// kernel supports ioctl on directories
        const FUSE_HAS_IOCTL_DIR = 1 << 11;
        /// automatically invalidate cached pages
        const FUSE_AUTO_INVAL_DATA = 1 << 12;
        /// do READDIRPLUS (READDIR+LOOKUP in one)
        const FUSE_DO_READDIRPLUS = 1 << 13;
        /// adaptive readdirplus
        const FUSE_READDIRPLUS_AUTO = 1 << 14;
        /// asynchronous direct I/O submission
        const FUSE_ASYNC_DIO = 1 << 15;
        /// use writeback cache for buffered writes
        const FUSE_WRITEBACK_CACHE = 1 << 16;
        /// kernel supports zero-message opens
        const FUSE_NO_OPEN_SUPPORT = 1 << 17;
        /// allow parallel lookups and readdir
        const FUSE_PARALLEL_DIROPS = 1 << 18;
        /// fs handles killing suid/sgid/cap on write/chown/trunc
        ///
        /// The filesystem takes responsibility for clearing suid, sgid and the
        /// `security.capability` xattr on every write, chown and truncate. No per-request
        /// signal accompanies this: the operation itself is the signal.
        ///
        /// Unlike [`Self::FUSE_HANDLE_KILLPRIV_V2`] this does not set `SB_NOSEC`, so the kernel
        /// still computes the removal and applies it through a `setattr`. What it buys is that
        /// the kernel skips refreshing attributes first, trusting the filesystem to keep them
        /// right.
        ///
        /// Note that this reaches further than the write, chown and truncate the contract names.
        /// Negotiating either killpriv capability also stops the kernel removing privileges on
        /// `fallocate` and `copy_file_range`, and neither carries a signal saying so, so a
        /// filesystem that wants those to behave like a local one has to clear the bits there
        /// itself
        const FUSE_HANDLE_KILLPRIV = 1 << 19;
        /// filesystem supports posix acls
        const FUSE_POSIX_ACL = 1 << 20;
        /// reading the device after abort returns ECONNABORTED
        const FUSE_ABORT_ERROR = 1 << 21;
        /// init_out.max_pages contains the max number of req pages
        const FUSE_MAX_PAGES = 1 << 22;
        /// cache READLINK responses
        const FUSE_CACHE_SYMLINKS = 1 << 23;
        /// kernel supports zero-message opendir
        const FUSE_NO_OPENDIR_SUPPORT = 1 << 24;
        /// only invalidate cached pages on explicit request
        const FUSE_EXPLICIT_INVAL_DATA = 1 << 25;
        /// map_alignment field is valid
        const FUSE_MAP_ALIGNMENT = 1 << 26;
        /// filesystem supports submounts
        const FUSE_SUBMOUNTS = 1 << 27;
        /// fs handles killing suid/sgid/cap on write/chown/trunc (v2)
        ///
        /// As with [`Self::FUSE_HANDLE_KILLPRIV`], clearing the `security.capability` xattr on
        /// every write, chown and truncate is the filesystem's job and carries no per-request
        /// signal. This capability additionally sets `SB_NOSEC`, which stops the kernel doing
        /// it, though only for an inode whose attributes are cached: fuse clears `S_NOSEC` on
        /// every attribute refresh, since another client may have set the xattr meanwhile. A
        /// filesystem therefore cannot rely on the kernel having done it.
        ///
        /// What v2 adds is finer control over suid and sgid alone, matching what the VFS would
        /// have done: they are cleared on a write or truncate only when the caller lacks
        /// `CAP_FSETID`, and sgid only when the file is group-executable. The kernel reports
        /// the cases it wants cleared through the `kill_suid_gid` argument of
        /// [`Filesystem::setattr`](crate::Filesystem::setattr),
        /// [`open`](crate::Filesystem::open) and [`create`](crate::Filesystem::create), and
        /// through [`WriteFlags::FUSE_WRITE_KILL_SUIDGID`](crate::WriteFlags) on a write.
        /// Honoring those covers suid and sgid only, not file capabilities, and only the
        /// operations that carry a signal: see [`Self::FUSE_HANDLE_KILLPRIV`] for the ones that
        /// do not
        const FUSE_HANDLE_KILLPRIV_V2 = 1 << 28;
        /// extended setxattr support
        const FUSE_SETXATTR_EXT = 1 << 29;
        /// extended fuse_init_in request
        const FUSE_INIT_EXT = 1 << 30;
        /// reserved, do not use
        const FUSE_INIT_RESERVED = 1 << 31;
        /// add security context to create/mkdir/symlink/mknod
        const FUSE_SECURITY_CTX = 1 << 32;
        /// filesystem supports per-inode DAX
        const FUSE_HAS_INODE_DAX = 1 << 33;
        /// create with supplementary group
        const FUSE_CREATE_SUPP_GROUP = 1 << 34;
        /// kernel supports expire-only invalidation
        const FUSE_HAS_EXPIRE_ONLY = 1 << 35;
        /// allow mmap for direct I/O files
        const FUSE_DIRECT_IO_ALLOW_MMAP = 1 << 36;
        /// filesystem wants to use passthrough files
        const FUSE_PASSTHROUGH = 1 << 37;
        /// filesystem does not support export
        const FUSE_NO_EXPORT_SUPPORT = 1 << 38;
        /// kernel supports resend requests
        const FUSE_HAS_RESEND = 1 << 39;
        /// allow idmapped mounts
        const FUSE_ALLOW_IDMAP = 1 << 40;
        /// kernel supports io_uring for communication
        const FUSE_OVER_IO_URING = 1 << 41;
        /// kernel supports request timeout
        const FUSE_REQUEST_TIMEOUT = 1 << 42;

        /// filesystem supports the `RENAME_SWAP` flag of `renamex_np(2)`.
        /// Requesting this also selects macFUSE's extended `fuse_rename_in` layout
        #[cfg(target_os = "macos")]
        const FUSE_RENAME_SWAP = 1 << 25;
        /// filesystem supports the `RENAME_EXCL` flag of `renamex_np(2)`.
        /// Requesting this also selects macFUSE's extended `fuse_rename_in` layout
        #[cfg(target_os = "macos")]
        const FUSE_RENAME_EXCL = 1 << 26;
        /// pre-allocate space for a file
        #[cfg(target_os = "macos")]
        const FUSE_ALLOCATE = 1 << 27;
        /// atomically exchange data between files
        #[cfg(target_os = "macos")]
        const FUSE_EXCHANGE_DATA = 1 << 28;
        /// filesystem is case-insensitive
        #[cfg(target_os = "macos")]
        const FUSE_CASE_INSENSITIVE = 1 << 29;
        /// filesystem supports volume renaming
        #[cfg(target_os = "macos")]
        const FUSE_VOL_RENAME = 1 << 30;
        /// filesystem supports extended times (backup and creation times)
        #[cfg(target_os = "macos")]
        const FUSE_XTIMES = 1 << 31;
    }
}

impl InitFlags {
    /// Returns the flags as a pair of (low, high) u32 values.
    /// The low value contains bits 0-31, the high value contains bits 32-63.
    pub(crate) fn pair(self) -> (u32, u32) {
        let bits = self.bits();
        (bits as u32, (bits >> 32) as u32)
    }
}
