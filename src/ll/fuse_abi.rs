//! FUSE kernel interface.
//!
//! Types and definitions used for communication between the kernel driver and the userspace
//! part of a FUSE filesystem. Since the kernel driver may be installed independently, the ABI
//! interface is versioned and capabilities are exchanged during the initialization (mounting)
//! of a filesystem.
//!
//! macfuse (macOS): <https://github.com/macfuse/library/blob/master/include/fuse_kernel.h>
//! - supports ABI 7.8 in OSXFUSE 2.x
//! - supports ABI 7.19 since OSXFUSE 3.0.0
//!
//! libfuse (Linux/BSD): <https://github.com/libfuse/libfuse/blob/master/include/fuse_kernel.h>
//! - supports ABI 7.8 since FUSE 2.6.0
//! - supports ABI 7.12 since FUSE 2.8.0
//! - supports ABI 7.18 since FUSE 2.9.0
//! - supports ABI 7.19 since FUSE 2.9.1
//! - supports ABI 7.26 since FUSE 3.0.0
//!
//! FreeBSD kernel headers: <https://github.com/freebsd/freebsd-src/blob/main/sys/fs/fuse/fuse_kernel.h>
//!
//! Items without a version annotation are valid with ABI 7.8 and later

#![warn(missing_debug_implementations)]
#![allow(missing_docs)]

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

pub(crate) const FUSE_KERNEL_VERSION: u32 = 7;

#[cfg(not(feature = "abi-7-20"))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 19;
#[cfg(all(feature = "abi-7-20", not(feature = "abi-7-21")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 20;
#[cfg(all(feature = "abi-7-21", not(feature = "abi-7-22")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 21;
#[cfg(all(feature = "abi-7-22", not(feature = "abi-7-23")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 22;
#[cfg(all(feature = "abi-7-23", not(feature = "abi-7-24")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 23;
#[cfg(all(feature = "abi-7-24", not(feature = "abi-7-25")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 24;
#[cfg(all(feature = "abi-7-25", not(feature = "abi-7-26")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 25;
#[cfg(all(feature = "abi-7-26", not(feature = "abi-7-27")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 26;
#[cfg(all(feature = "abi-7-27", not(feature = "abi-7-28")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 27;
#[cfg(all(feature = "abi-7-28", not(feature = "abi-7-29")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 28;
#[cfg(all(feature = "abi-7-29", not(feature = "abi-7-30")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 29;
#[cfg(all(feature = "abi-7-30", not(feature = "abi-7-31")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 30;
#[cfg(all(feature = "abi-7-31", not(feature = "abi-7-36")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
#[cfg(all(feature = "abi-7-36", not(feature = "abi-7-40")))]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 36;
#[cfg(feature = "abi-7-40")]
pub(crate) const FUSE_KERNEL_MINOR_VERSION: u32 = 40;

#[repr(C)]
#[derive(Debug, IntoBytes, Clone, Copy, KnownLayout, Immutable)]
pub(crate) struct fuse_attr {
    pub(crate) ino: u64,
    pub(crate) size: u64,
    pub(crate) blocks: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_atime
    pub(crate) atime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_mtime
    pub(crate) mtime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_ctime
    pub(crate) ctime: i64,
    #[cfg(target_os = "macos")]
    pub(crate) crtime: u64,
    pub(crate) atimensec: u32,
    pub(crate) mtimensec: u32,
    pub(crate) ctimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) crtimensec: u32,
    pub(crate) mode: u32,
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) rdev: u32,
    #[cfg(target_os = "macos")]
    pub(crate) flags: u32, // see chflags(2)
    pub(crate) blksize: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_kstatfs {
    pub(crate) blocks: u64,  // Total blocks (in units of frsize)
    pub(crate) bfree: u64,   // Free blocks
    pub(crate) bavail: u64,  // Free blocks for unprivileged users
    pub(crate) files: u64,   // Total inodes
    pub(crate) ffree: u64,   // Free inodes
    pub(crate) bsize: u32,   // Filesystem block size
    pub(crate) namelen: u32, // Maximum filename length
    pub(crate) frsize: u32,  // Fundamental file system block size
    pub(crate) padding: u32,
    pub(crate) spare: [u32; 6],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_file_lock {
    pub(crate) start: u64,
    pub(crate) end: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) typ: i32,
    pub(crate) pid: u32,
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

pub mod consts {
    // Getattr flags
    pub const FUSE_GETATTR_FH: u32 = 1 << 0;

    // Lock flags
    pub const FUSE_LK_FLOCK: u32 = 1 << 0;

    // IOCTL constant
    pub const FUSE_IOCTL_MAX_IOV: u32 = 256; // maximum of in_iovecs + out_iovecs

    // The read buffer is required to be at least 8k, but may be much larger
    pub const FUSE_MIN_READ_BUFFER: usize = 8192;
}

#[repr(u32)]
#[derive(Debug, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub(crate) enum fuse_opcode {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2, // no reply
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    FUSE_IOCTL = 39,
    FUSE_POLL = 40,
    FUSE_NOTIFY_REPLY = 41,
    FUSE_BATCH_FORGET = 42,
    FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44,
    FUSE_RENAME2 = 45,
    FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47,

    #[cfg(target_os = "macos")]
    FUSE_SETVOLNAME = 61,
    #[cfg(target_os = "macos")]
    FUSE_GETXTIMES = 62,
    #[cfg(target_os = "macos")]
    FUSE_EXCHANGE = 63,

    CUSE_INIT = 4096,
}

#[repr(u32)]
#[derive(Debug, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub(crate) enum fuse_notify_code {
    FUSE_POLL = 1,
    FUSE_NOTIFY_INVAL_INODE = 2,
    FUSE_NOTIFY_INVAL_ENTRY = 3,
    FUSE_NOTIFY_STORE = 4,
    FUSE_NOTIFY_RETRIEVE = 5,
    FUSE_NOTIFY_DELETE = 6,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_entry_out {
    pub(crate) nodeid: u64,
    pub(crate) generation: u64,
    pub(crate) entry_valid: u64,
    pub(crate) attr_valid: u64,
    pub(crate) entry_valid_nsec: u32,
    pub(crate) attr_valid_nsec: u32,
    pub(crate) attr: fuse_attr,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_forget_in {
    pub(crate) nlookup: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub struct fuse_forget_one {
    pub nodeid: u64,
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_batch_forget_in {
    pub(crate) count: u32,
    pub(crate) dummy: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getattr_in {
    pub(crate) getattr_flags: u32,
    pub(crate) dummy: u32,
    pub(crate) fh: u64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_attr_out {
    pub(crate) attr_valid: u64,
    pub(crate) attr_valid_nsec: u32,
    pub(crate) dummy: u32,
    pub(crate) attr: fuse_attr,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getxtimes_out {
    pub(crate) bkuptime: u64,
    pub(crate) crtime: u64,
    pub(crate) bkuptimensec: u32,
    pub(crate) crtimensec: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_mknod_in {
    pub(crate) mode: u32,
    pub(crate) rdev: u32,
    pub(crate) umask: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_mkdir_in {
    pub(crate) mode: u32,
    pub(crate) umask: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_rename_in {
    pub(crate) newdir: u64,
    #[cfg(feature = "macfuse-4-compat")]
    pub(crate) flags: u32,
    #[cfg(feature = "macfuse-4-compat")]
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_rename2_in {
    pub(crate) newdir: u64,
    pub(crate) flags: u32,
    pub(crate) padding: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_exchange_in {
    pub(crate) olddir: u64,
    pub(crate) newdir: u64,
    pub(crate) options: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_link_in {
    pub(crate) oldnodeid: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_setattr_in {
    pub(crate) valid: u32,
    pub(crate) padding: u32,
    pub(crate) fh: u64,
    pub(crate) size: u64,
    pub(crate) lock_owner: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_atime
    pub(crate) atime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_mtime
    pub(crate) mtime: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    // to match stat.st_ctime
    pub(crate) ctime: i64, // Used since ABI 7.23.
    pub(crate) atimensec: u32,
    pub(crate) mtimensec: u32,
    pub(crate) ctimensec: u32, // Used since ABI 7.23.
    pub(crate) mode: u32,
    pub(crate) unused4: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) unused5: u32,
    #[cfg(target_os = "macos")]
    pub(crate) bkuptime: u64,
    #[cfg(target_os = "macos")]
    pub(crate) chgtime: u64,
    #[cfg(target_os = "macos")]
    pub(crate) crtime: u64,
    #[cfg(target_os = "macos")]
    pub(crate) bkuptimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) chgtimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) crtimensec: u32,
    #[cfg(target_os = "macos")]
    pub(crate) flags: u32, // see chflags(2)
}

impl fuse_setattr_in {
    pub(crate) fn atime_now(&self) -> bool {
        FattrFlags::from_bits_retain(self.valid).contains(FattrFlags::FATTR_ATIME_NOW)
    }

    pub(crate) fn mtime_now(&self) -> bool {
        FattrFlags::from_bits_retain(self.valid).contains(FattrFlags::FATTR_MTIME_NOW)
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_open_in {
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's open method and this matches the open() syscall
    pub(crate) flags: i32,
    pub(crate) unused: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_create_in {
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's create method and this matches the open() syscall
    pub(crate) flags: i32,
    pub(crate) mode: u32,
    pub(crate) umask: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_create_out(pub(crate) fuse_entry_out, pub(crate) fuse_open_out);

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_open_out {
    pub(crate) fh: u64,
    pub(crate) open_flags: u32,
    pub(crate) backing_id: u32, // Used since ABI 7.40.
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_release_in {
    pub(crate) fh: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's read method
    pub(crate) flags: i32,
    pub(crate) release_flags: u32,
    pub(crate) lock_owner: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_flush_in {
    pub(crate) fh: u64,
    pub(crate) unused: u32,
    pub(crate) padding: u32,
    pub(crate) lock_owner: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_read_in {
    pub(crate) fh: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) read_flags: u32,
    pub(crate) lock_owner: u64,
    pub(crate) flags: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_write_in {
    pub(crate) fh: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i64 when invoking the filesystem's write method
    pub(crate) offset: i64,
    pub(crate) size: u32,
    pub(crate) write_flags: u32,
    pub(crate) lock_owner: u64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's read method
    pub(crate) flags: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_write_out {
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_statfs_out {
    pub(crate) st: fuse_kstatfs,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_fsync_in {
    pub(crate) fh: u64,
    pub(crate) fsync_flags: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_setxattr_in {
    pub(crate) size: u32,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's setxattr method
    pub(crate) flags: i32,
    #[cfg(target_os = "macos")]
    pub(crate) position: u32,
    #[cfg(target_os = "macos")]
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getxattr_in {
    pub(crate) size: u32,
    pub(crate) padding: u32,
    #[cfg(target_os = "macos")]
    pub(crate) position: u32,
    #[cfg(target_os = "macos")]
    pub(crate) padding2: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_getxattr_out {
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lk_in {
    pub(crate) fh: u64,
    pub(crate) owner: u64,
    pub(crate) lk: fuse_file_lock,
    pub(crate) lk_flags: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lk_out {
    pub(crate) lk: fuse_file_lock,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_access_in {
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is then cast
    // to an i32 when invoking the filesystem's access method
    pub(crate) mask: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable, IntoBytes)]
pub(crate) struct fuse_init_in {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) max_readahead: u32,
    pub(crate) flags: u32,
    pub(crate) flags2: u32,
    pub(crate) unused: [u32; 11],
}

pub(crate) const FUSE_COMPAT_INIT_OUT_SIZE: usize = 8;
pub(crate) const FUSE_COMPAT_22_INIT_OUT_SIZE: usize = 24;

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_init_out {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) max_readahead: u32,
    pub(crate) flags: u32,
    pub(crate) max_background: u16,
    pub(crate) congestion_threshold: u16,
    pub(crate) max_write: u32,
    pub(crate) time_gran: u32,
    pub(crate) max_pages: u16,
    pub(crate) unused2: u16,
    pub(crate) flags2: u32,
    pub(crate) max_stack_depth: u32,
    pub(crate) reserved: [u32; 6],
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct cuse_init_in {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) unused: u32,
    pub(crate) flags: u32,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable)]
pub(crate) struct cuse_init_out {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) unused: u32,
    pub(crate) flags: u32,
    pub(crate) max_read: u32,
    pub(crate) max_write: u32,
    pub(crate) dev_major: u32, // chardev major
    pub(crate) dev_minor: u32, // chardev minor
    pub(crate) spare: [u32; 10],
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_interrupt_in {
    pub(crate) unique: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_bmap_in {
    pub(crate) block: u64,
    pub(crate) blocksize: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_bmap_out {
    pub(crate) block: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_ioctl_in {
    pub(crate) fh: u64,
    pub(crate) flags: u32,
    pub(crate) cmd: u32,
    pub(crate) arg: u64,
    pub(crate) in_size: u32,
    pub(crate) out_size: u32,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable)]
pub(crate) struct fuse_ioctl_iovec {
    pub(crate) base: u64,
    pub(crate) len: u64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_ioctl_out {
    pub(crate) result: i32,
    pub(crate) flags: u32,
    pub(crate) in_iovs: u32,
    pub(crate) out_iovs: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_poll_in {
    pub(crate) fh: u64,
    pub(crate) kh: u64,
    pub(crate) flags: u32,
    pub(crate) events: u32, // Used since ABI 7.21.
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_poll_out {
    pub(crate) revents: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_poll_wakeup_out {
    pub(crate) kh: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_fallocate_in {
    pub(crate) fh: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) offset: i64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) length: i64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) mode: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_in_header {
    pub(crate) len: u32,
    pub(crate) opcode: u32,
    pub(crate) unique: u64,
    pub(crate) nodeid: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) pid: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_out_header {
    pub(crate) len: u32,
    pub(crate) error: i32,
    pub(crate) unique: u64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_dirent {
    pub(crate) ino: u64,
    pub(crate) off: u64,
    pub(crate) namelen: u32,
    pub(crate) typ: u32,
    // followed by name of namelen bytes
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_direntplus {
    pub(crate) entry_out: fuse_entry_out,
    pub(crate) dirent: fuse_dirent,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_inval_inode_out {
    pub(crate) ino: u64,
    pub(crate) off: i64,
    pub(crate) len: i64,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_inval_entry_out {
    pub(crate) parent: u64,
    pub(crate) namelen: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_delete_out {
    pub(crate) parent: u64,
    pub(crate) child: u64,
    pub(crate) namelen: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_store_out {
    pub(crate) nodeid: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_retrieve_out {
    pub(crate) notify_unique: u64,
    pub(crate) nodeid: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_notify_retrieve_in {
    // matches the size of fuse_write_in
    pub(crate) dummy1: u64,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) dummy2: u32,
    pub(crate) dummy3: u64,
    pub(crate) dummy4: u64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lseek_in {
    pub(crate) fh: u64,
    pub(crate) offset: i64,
    // NOTE: this field is defined as u32 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) whence: i32,
    pub(crate) padding: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_lseek_out {
    pub(crate) offset: i64,
}

#[repr(C)]
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
pub(crate) struct fuse_copy_file_range_in {
    pub(crate) fh_in: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) off_in: i64,
    pub(crate) nodeid_out: u64,
    pub(crate) fh_out: u64,
    // NOTE: this field is defined as u64 in fuse_kernel.h in libfuse. However, it is treated as signed
    pub(crate) off_out: i64,
    pub(crate) len: u64,
    pub(crate) flags: u64,
}
