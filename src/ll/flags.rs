use std::fmt::Display;
use std::fmt::Formatter;

use bitflags::bitflags;

bitflags! {
    /// Flags of `copy_file_range`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CopyFileRangeFlags: u64 {}
}

bitflags! {
    /// CUSE init flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct CuseInitFlags: u32 {
        /// Use unrestricted ioctl.
        const CUSE_UNRESTRICTED_IOCTL = 1 << 0;
    }
}

impl Display for CuseInitFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.bits(), f)
    }
}

bitflags! {
    /// Fsync flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FsyncFlags: u32 {
        /// Sync data only, not metadata.
        const FUSE_FSYNC_FDATASYNC = 1 << 0;
    }
}

impl Display for FsyncFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.bits(), f)
    }
}

bitflags! {
    /// Ioctl flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct IoctlFlags: u32 {
        /// 32bit compat ioctl on 64bit machine.
        const FUSE_IOCTL_COMPAT = 1 << 0;
        /// Not restricted to well-formed ioctls, retry allowed.
        const FUSE_IOCTL_UNRESTRICTED = 1 << 1;
        /// Retry with new iovecs.
        const FUSE_IOCTL_RETRY = 1 << 2;
        /// 32bit ioctl.
        const FUSE_IOCTL_32BIT = 1 << 3;
        /// Is a directory.
        const FUSE_IOCTL_DIR = 1 << 4;
        /// x32 compat ioctl on 64bit machine (64bit time_t).
        const FUSE_IOCTL_COMPAT_X32 = 1 << 5;
    }
}

impl Display for IoctlFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.bits(), f)
    }
}

bitflags! {
    /// Poll flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PollFlags: u32 {
        /// Request poll notify.
        const FUSE_POLL_SCHEDULE_NOTIFY = 1 << 0;
    }
}

impl Display for PollFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.bits(), f)
    }
}

bitflags! {
    /// Read flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ReadFlags: u32 {
        /// Indicates that `fuse_read_in.lock_owner` contains lock owner.
        /// Users typically do not need to check this flag.
        const FUSE_READ_LOCKOWNER = 1 << 1;
    }
}

bitflags! {
    /// Release flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct ReleaseFlags: u32 {
        /// Flush the file on release.
        const FUSE_RELEASE_FLUSH = 1 << 0;
        /// Unlock flock on release.
        const FUSE_RELEASE_FLOCK_UNLOCK = 1 << 1;
    }
}

impl Display for ReleaseFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.bits(), f)
    }
}

bitflags! {
    /// Write flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct WriteFlags: u32 {
        /// Delayed write from page cache, file handle is guessed.
        const FUSE_WRITE_CACHE = 1 << 0;
        /// lock_owner field is valid.
        const FUSE_WRITE_LOCKOWNER = 1 << 1;
        /// Kill suid and sgid bits.
        const FUSE_WRITE_KILL_SUIDGID = 1 << 2;
    }
}

bitflags! {
    /// Flags returned in open response.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FopenFlags: u32 {
        /// bypass page cache for this open file
        const FOPEN_DIRECT_IO = 1 << 0;
        /// don't invalidate the data cache on open
        const FOPEN_KEEP_CACHE = 1 << 1;
        /// the file is not seekable
        const FOPEN_NONSEEKABLE = 1 << 2;
        /// allow caching this directory
        const FOPEN_CACHE_DIR = 1 << 3;
        /// the file is stream-like (no file position at all)
        const FOPEN_STREAM = 1 << 4;
        /// kernel skips sending FUSE_FLUSH on close
        const FOPEN_NOFLUSH = 1 << 5;
        /// allow multiple concurrent writes on the same direct-IO file
        const FOPEN_PARALLEL_DIRECT_WRITES = 1 << 6;
        /// the file is fd-backed (via the backing_id field)
        const FOPEN_PASSTHROUGH = 1 << 7;
        #[cfg(target_os = "macos")]
        const FOPEN_PURGE_ATTR = 1 << 30;
        #[cfg(target_os = "macos")]
        const FOPEN_PURGE_UBC = 1 << 31;
    }
}

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

        #[cfg(target_os = "macos")]
        const FUSE_ALLOCATE = 1 << 27;
        #[cfg(target_os = "macos")]
        const FUSE_EXCHANGE_DATA = 1 << 28;
        #[cfg(target_os = "macos")]
        const FUSE_CASE_INSENSITIVE = 1 << 29;
        #[cfg(target_os = "macos")]
        const FUSE_VOL_RENAME = 1 << 30;
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
