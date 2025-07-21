//! FUSE userspace library implementation
//!
//! This is an improved rewrite of the FUSE userspace library (lowlevel interface) to fully take
//! advantage of Rust's architecture. The only thing we rely on in the real libfuse are mount
//! and unmount calls which are needed to establish a fd to talk to the kernel driver.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[allow(unused_imports)]
use log::{debug, info, warn, error};
use mnt::mount_options::parse_options_from_args;
/* 
#[cfg(feature = "serializable")]
use serde::de::value::F64Deserializer;
#[cfg(feature = "serializable")]
use serde::{Deserialize, Serialize};
*/
use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};
use std::{convert::AsRef, io::ErrorKind};
#[allow(clippy::wildcard_imports)] // avoid duplicating feature gates
use crate::ll::fuse_abi::consts::*;
pub use crate::ll::fuse_abi::FUSE_ROOT_ID;
pub use crate::ll::{fuse_abi::consts, TimeOrNow};
pub use ll::Errno;
use crate::mnt::mount_options::check_option_conflicts;
use crate::session::MAX_WRITE_SIZE;
pub use mnt::mount_options::MountOption;
#[cfg(feature = "abi-7-11")]
pub use notify::{Notification, Poll};
#[cfg(feature = "abi-7-12")]
pub use notify::{InvalEntry, InvalInode};
#[cfg(feature = "abi-7-15")]
pub use notify::Store;
#[cfg(feature = "abi-7-18")]
pub use notify::Delete;
#[cfg(feature = "abi-7-11")]
pub use reply::Ioctl;
#[cfg(target_os = "macos")]
pub use reply::XTimes;
pub use reply::{Bytes, Entry, FileAttr, FileType, Dirent, DirentList, DirentPlusList, Open, Statfs, Xattr, Lock};
pub use request::RequestMeta;
pub use session::{BackgroundSession, Session, SessionACL, SessionUnmounter};
pub use container::{Container, Borrow};

#[cfg(feature = "abi-7-28")]
use std::cmp::max;
#[cfg(feature = "abi-7-13")]
use std::cmp::min;

mod channel;
mod container;
mod ll;
mod mnt;
#[cfg(feature = "abi-7-11")]
mod notify;
mod reply;
mod request;
mod session;

/// We generally support async reads
#[cfg(all(not(target_os = "macos"), not(feature = "abi-7-10")))]
const INIT_FLAGS: u64 = FUSE_ASYNC_READ;
#[cfg(all(not(target_os = "macos"), feature = "abi-7-10"))]
const INIT_FLAGS: u64 = FUSE_ASYNC_READ | FUSE_BIG_WRITES;
// TODO: Add FUSE_EXPORT_SUPPORT

/// On macOS, we additionally support case insensitiveness, volume renames and xtimes
/// TODO: we should eventually let the filesystem implementation decide which flags to set
#[cfg(target_os = "macos")]
const INIT_FLAGS: u64 = FUSE_ASYNC_READ | FUSE_CASE_INSENSITIVE | FUSE_VOL_RENAME | FUSE_XTIMES;
// TODO: Add FUSE_EXPORT_SUPPORT and FUSE_BIG_WRITES (requires ABI 7.10)

#[allow(unused_variables)]
const fn default_init_flags(capabilities: u64) -> u64 {
    #[cfg(not(feature = "abi-7-28"))]
    {
        INIT_FLAGS
    }

    #[cfg(feature = "abi-7-28")]
    {
        let mut flags = INIT_FLAGS;
        if capabilities & FUSE_MAX_PAGES != 0 {
            flags |= FUSE_MAX_PAGES;
        }
        flags
    }
}

#[derive(Debug)]
/// Target of a `forget` or `batch_forget` operation.
pub struct Forget {
    /// Inode of the file to be forgotten.
    pub ino: u64,
    /// The number of times the file has been looked up (and not yet forgotten).
    /// When a `forget` operation is received, the filesystem should typically
    /// decrement its internal reference count for the inode by `nlookup`.
    pub nlookup: u64
}

/// Configuration of the fuse kernel module connection
#[derive(Debug)]
pub struct KernelConfig {
    capabilities: u64,
    requested: u64,
    max_readahead: u32,
    max_max_readahead: u32,
    #[cfg(feature = "abi-7-13")]
    max_background: u16,
    #[cfg(feature = "abi-7-13")]
    congestion_threshold: Option<u16>,
    max_write: u32,
    #[cfg(feature = "abi-7-23")]
    time_gran: Duration,
    #[cfg(feature = "abi-7-40")]
    max_stack_depth: u32,
}

impl KernelConfig {
    fn new(capabilities: u64, max_readahead: u32) -> Self {
        Self {
            capabilities,
            requested: default_init_flags(capabilities),
            max_readahead,
            max_max_readahead: max_readahead,
            #[cfg(feature = "abi-7-13")]
            max_background: 16,
            #[cfg(feature = "abi-7-13")]
            congestion_threshold: None,
            // use a max write size that fits into the session's buffer
            max_write: MAX_WRITE_SIZE as u32,
            // 1ns means nano-second granularity.
            #[cfg(feature = "abi-7-23")]
            time_gran: Duration::new(0, 1),
            #[cfg(feature = "abi-7-40")]
            max_stack_depth: 0,
        }
    }

    /// Set the maximum stacking depth of the filesystem
    ///
    /// This has to be at least 1 to support passthrough to backing files.  Setting this to 0 (the
    /// default) effectively disables support for passthrough.
    ///
    /// With `max_stack_depth` > 1, the backing files can be on a stacked fs (e.g. overlayfs)
    /// themselves and with `max_stack_depth` == 1, this FUSE filesystem can be stacked as the
    /// underlying fs of a stacked fs (e.g. overlayfs).
    ///
    /// The kernel currently has a hard maximum value of 2.  Anything higher won't work.
    /// # Errors
    /// On success, returns the previous value.  On error, returns the nearest value which will succeed.
    #[cfg(feature = "abi-7-40")]
    pub fn set_max_stack_depth(&mut self, value: u32) -> Result<u32, u32> {
        // https://lore.kernel.org/linux-fsdevel/CAOYeF9V_n93OEF_uf0Gwtd=+da0ReX8N2aaT6RfEJ9DPvs8O2w@mail.gmail.com/
        const FILESYSTEM_MAX_STACK_DEPTH: u32 = 2;

        if value > FILESYSTEM_MAX_STACK_DEPTH {
            return Err(FILESYSTEM_MAX_STACK_DEPTH);
        }

        let previous = self.max_stack_depth;
        self.max_stack_depth = value;
        Ok(previous)
    }

    /// Set the timestamp granularity
    ///
    /// Must be a power of 10 nanoseconds. i.e. 1s, 0.1s, 0.01s, 1ms, 0.1ms...etc
    /// # Errors
    /// On success returns the previous value. On error returns the nearest value which will succeed.
    #[cfg(feature = "abi-7-23")]
    pub fn set_time_granularity(&mut self, value: Duration) -> Result<Duration, Duration> {
        if value.as_nanos() == 0 {
            return Err(Duration::new(0, 1));
        }
        if value.as_secs() > 1 || (value.as_secs() == 1 && value.subsec_nanos() > 0) {
            return Err(Duration::new(1, 0));
        }
        let mut power_of_10 = 1;
        while power_of_10 < value.as_nanos() {
            if value.as_nanos() < power_of_10 * 10 {
                // value must not be a power of ten, since power_of_10 < value < power_of_10 * 10
                return Err(Duration::new(0, power_of_10 as u32));
            }
            power_of_10 *= 10;
        }
        let previous = self.time_gran;
        self.time_gran = value;
        Ok(previous)
    }

    /// Set the maximum write size for a single request
    /// # Errors
    /// On success returns the previous value. On error returns the nearest value which will succeed.
    pub fn set_max_write(&mut self, value: u32) -> Result<u32, u32> {
        if value == 0 {
            return Err(1);
        }
        if value > MAX_WRITE_SIZE as u32 {
            return Err(MAX_WRITE_SIZE as u32);
        }
        let previous = self.max_write;
        self.max_write = value;
        Ok(previous)
    }

    /// Set the maximum readahead size
    /// # Errors
    /// On success returns the previous value. On error returns the nearest value which will succeed.
    pub fn set_max_readahead(&mut self, value: u32) -> Result<u32, u32> {
        if value == 0 {
            return Err(1);
        }
        if value > self.max_max_readahead {
            return Err(self.max_max_readahead);
        }
        let previous = self.max_readahead;
        self.max_readahead = value;
        Ok(previous)
    }

    /// Add a set of capabilities.
    /// # Errors
    /// On success returns Ok. On error, returns the bits of capabilities not supported by kernel.
    pub fn add_capabilities(&mut self, capabilities_to_add: u64) -> Result<(), u64> {
        if capabilities_to_add & self.capabilities != capabilities_to_add {
            return Err(capabilities_to_add - (capabilities_to_add & self.capabilities));
        }
        self.requested |= capabilities_to_add;
        Ok(())
    }

    /// Set the maximum number of pending background requests. Such as readahead requests.
    /// # Errors
    /// On success returns the previous value. On error returns the nearest value which will succeed
    #[cfg(feature = "abi-7-13")]
    pub fn set_max_background(&mut self, value: u16) -> Result<u16, u16> {
        if value == 0 {
            return Err(1);
        }
        let previous = self.max_background;
        self.max_background = value;
        Ok(previous)
    }

    /// Set the threshold of background requests at which the kernel will consider the filesystem
    /// request queue congested. (it may then switch to sleeping instead of spin-waiting, for example)
    /// # Errors
    /// On success returns the previous value. On error returns the nearest value which will succeed.
    #[cfg(feature = "abi-7-13")]
    pub fn set_congestion_threshold(&mut self, value: u16) -> Result<u16, u16> {
        if value == 0 {
            return Err(1);
        }
        let previous = self.congestion_threshold();
        self.congestion_threshold = Some(value);
        Ok(previous)
    }

    #[cfg(feature = "abi-7-13")]
    fn congestion_threshold(&self) -> u16 {
        match self.congestion_threshold {
            // Default to a threshold of 3/4 of the max background threads
            None => (u32::from(self.max_background) * 3 / 4) as u16,
            Some(value) => min(value, self.max_background),
        }
    }

    #[cfg(feature = "abi-7-28")]
    #[allow(clippy::cast_possible_truncation)] // truncation is a feature of this computation
    fn max_pages(&self) -> u16 {
        ((max(self.max_write, self.max_readahead) - 1) / page_size::get() as u32) as u16 + 1
    }
}

#[derive(Debug)]
/// This enum is an optional way for the Filesystem to report its status to a Session thread.
pub enum FsStatus {
    /// Default may be used when the Filesystem does not implement a status
    Default,
    /// Ready indicates the Filesystem has no actions in progress
    Ready,
    /// Busy indicates the Filesytem has one or more actions in progress
    Busy,
    /// Stopped indicates that the Filesystem will not accept new requests
    Stopped
}

/// Filesystem trait.
///
/// This trait must be implemented to provide a userspace filesystem via FUSE.
/// These methods correspond to `fuse_lowlevel_ops` in libfuse. Reasonable default
/// implementations are provided here to get a mountable filesystem that does
/// nothing.
#[allow(clippy::too_many_arguments)]
#[allow(unused_variables)] // This is the main API, so variables are named without the underscore even though the defaults may not use them.
#[allow(clippy::missing_errors_doc)] // These default implementations do not define the conditions that cause errors
pub trait Filesystem {
    /// Initialize filesystem.
    /// Called before any other filesystem method.
    /// The kernel module connection can be configured using the `KernelConfig` object.
    /// The method should return `Ok(KernelConfig)` to accept the connection, or `Err(Errno)` to reject it.
    fn init(&mut self, req: RequestMeta, config: KernelConfig) -> Result<KernelConfig, Errno> {
        Ok(config)
    }

    /// Clean up filesystem.
    /// Called on filesystem exit.
    fn destroy(&mut self) {}

    /// Look up a directory entry by name and get its attributes.
    /// The method should return `Ok(Entry)` if the entry is found, or `Err(Errno)` otherwise.
    fn lookup(&mut self, req: RequestMeta, parent: u64, name: &Path) -> Result<Entry, Errno> {
        warn!("[Not Implemented] lookup(parent: {parent:#x?}, name {name:?})");
        Err(Errno::ENOSYS)
    }

    /// Forget about an inode.
    /// The `target.nlookup` parameter indicates the number of lookups previously performed on
    /// this inode. If the filesystem implements inode lifetimes, it is recommended that
    /// inodes acquire a single reference on each lookup, and lose `target.nlookup` references on
    /// each forget. The filesystem may ignore forget calls, if the inodes don't need to
    /// have a limited lifetime. On unmount it is not guaranteed, that all referenced
    /// inodes will receive a forget message. This operation does not return a result.
    fn forget(&mut self, req: RequestMeta, target: Forget) {}

    /// Like forget, but take multiple forget requests at once for performance. The default
    /// implementation will fallback to `forget` for each node. This operation does not return a result.
    #[cfg(feature = "abi-7-16")]
    fn batch_forget(&mut self, req: RequestMeta, nodes: Vec<Forget>) {
        for node in nodes {
            self.forget(req, node);
        }
    }

    /// Get file attributes.
    /// The method should return `Ok(Attr)` with the file attributes, or `Err(Errno)` otherwise.
    fn getattr(&mut self, req: RequestMeta, ino: u64, fh: Option<u64>) -> Result<(FileAttr, Duration), Errno> {
        warn!("[Not Implemented] getattr(ino: {ino:#x?}, fh: {fh:#x?})");
        Err(Errno::ENOSYS)
    }

    /// Set file attributes.
    /// The method should return `Ok(Attr)` with the updated file attributes, or `Err(Errno)` otherwise.
    fn setattr(
        &mut self,
        req: RequestMeta,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>
    ) -> Result<(FileAttr, std::time::Duration), Errno> {
        warn!(
            "[Not Implemented] setattr(ino: {ino:#x?}, mode: {mode:?}, uid: {uid:?}, \
            gid: {gid:?}, size: {size:?}, fh: {fh:?}, flags: {flags:?})"
        );
        Err(Errno::ENOSYS)
    }

    /// Read symbolic link.
    /// The method should return `Ok(Bytes<'a>)` with the link target (an OS native string),
    /// or `Err(Errno)` otherwise.
    /// `Bytes` allows for returning data under various ownership models potentially avoiding a copy.
    fn readlink<'a>(&mut self, req: RequestMeta, ino: u64) -> Result<Bytes<'a>, Errno> {
        warn!("[Not Implemented] readlink(ino: {ino:#x?})");
        Err(Errno::ENOSYS)
    }

    /// Create file node.
    /// Create a regular file, character device, block device, fifo or socket node.
    /// The method should return `Ok(Entry)` with the new entry's attributes, or `Err(Errno)` otherwise.
    fn mknod(
        &mut self,
        req: RequestMeta,
        parent: u64,
        name: &Path,
        mode: u32,
        umask: u32,
        rdev: u32,
    ) -> Result<Entry, Errno> {
        warn!(
            "[Not Implemented] mknod(parent: {parent:#x?}, name: {name:?}, mode: {mode}, \
            umask: {umask:#x?}, rdev: {rdev})"
        );
        Err(Errno::ENOSYS)
    }

    /// Create a directory.
    /// The method should return `Ok(Entry)` with the new directory's attributes, or `Err(Errno)` otherwise.
    fn mkdir(
        &mut self,
        req: RequestMeta,
        parent: u64,
        name: &Path,
        mode: u32,
        umask: u32,
    ) -> Result<Entry, Errno> {
        warn!("[Not Implemented] mkdir(parent: {parent:#x?}, name: {name:?}, mode: {mode}, umask: {umask:#x?})");
        Err(Errno::ENOSYS)
    }

    /// Remove a file.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn unlink(&mut self, req: RequestMeta, parent: u64, name: &Path) -> Result<(), Errno> {
        warn!("[Not Implemented] unlink(parent: {parent:#x?}, name: {name:?})");
        Err(Errno::ENOSYS)
    }

    /// Remove a directory.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn rmdir(&mut self, req: RequestMeta, parent: u64, name: &Path) -> Result<(), Errno> {
        warn!("[Not Implemented] rmdir(parent: {parent:#x?}, name: {name:?})");
        Err(Errno::ENOSYS)
    }

    /// Create a symbolic link.
    /// The method should return `Ok(Entry)` with the new link's attributes, or `Err(Errno)` otherwise.
    fn symlink(
        &mut self,
        req: RequestMeta,
        parent: u64,
        link_name: &Path,
        target: &Path,
    ) -> Result<Entry, Errno> {
        warn!("[Not Implemented] symlink(parent: {parent:#x?}, link_name: {link_name:?}, target: {target:?})");
        Err(Errno::EPERM) // why isn't this ENOSYS?
    }

    /// Rename a file.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    /// `flags` may be `RENAME_EXCHANGE` or `RENAME_NOREPLACE`.
    fn rename(
        &mut self,
        req: RequestMeta,
        parent: u64,
        name: &Path,
        newparent: u64,
        newname: &Path,
        flags: u32,
    ) -> Result<(), Errno> {
        warn!(
            "[Not Implemented] rename(parent: {parent:#x?}, name: {name:?}, newparent: {newparent:#x?}, \
            newname: {newname:?}, flags: {flags})",
        );
        Err(Errno::ENOSYS)
    }

    /// Create a hard link.
    /// The method should return `Ok(Entry)` with the new link's attributes, or `Err(Errno)` otherwise.
    fn link(
        &mut self,
        req: RequestMeta,
        ino: u64,
        newparent: u64,
        newname: &Path,
    ) -> Result<Entry, Errno> {
        warn!("[Not Implemented] link(ino: {ino:#x?}, newparent: {newparent:#x?}, newname: {newname:?})");
        Err(Errno::EPERM) // why isn't this ENOSYS?
    }

    /// Open a file.
    /// Open flags (with the exception of `O_CREAT`, `O_EXCL`, `O_NOCTTY` and `O_TRUNC`) are
    /// available in `flags`. Filesystem may store an arbitrary file handle (pointer, index,
    /// etc) in `Open.fh`, and use this in other all other file operations (read, write, flush,
    /// release, fsync). Filesystem may also implement stateless file I/O and not store
    /// anything in `Open.fh`. There are also some flags (`direct_io`, `keep_cache`) which the
    /// filesystem may set in `Open.flags`, to change the way the file is opened. See `fuse_file_info`
    /// structure in `<fuse_common.h>` for more details.
    /// The method should return `Ok(Open)` on success, or `Err(Errno)` otherwise.
    fn open(&mut self, req: RequestMeta, ino: u64, flags: i32) -> Result<Open, Errno> {
        warn!("[Not Implemented] open(ino: {ino:#x?}, flags: {flags})");
        Err(Errno::ENOSYS)
    }

    /// Read data.
    /// Read should return exactly the number of bytes requested except on EOF or error,
    /// otherwise the rest of the data will be substituted with zeroes. An exception to
    /// this is when the file has been opened in '`direct_io`' mode, in which case the
    /// return value of the read system call will reflect the return value of this
    /// operation. `fh` will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value.
    /// The method should return `Ok(Bytes<'a>)` with the read data, or `Err(Errno)` otherwise.
    /// `Bytes` allows for returning borrowed or owned data, potentially avoiding data copies.
    ///
    /// `flags`: these are the file flags, such as `O_SYNC`. Only supported with ABI >= 7.9
    /// `lock_owner`: only supported with ABI >= 7.9
    fn read<'a>(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
    ) -> Result<Bytes<'a>, Errno> {
        warn!(
            "[Not Implemented] read(ino: {ino:#x?}, fh: {fh}, offset: {offset}, size: {size}, \
            flags: {flags:#x?}, lock_owner: {lock_owner:?})"
        );
        Err(Errno::ENOSYS)
    }

    /// Write data.
    /// Write should return exactly the number of bytes requested except on error. An
    /// exception to this is when the file has been opened in '`direct_io`' mode, in
    /// which case the return value of the write system call will reflect the return
    /// value of this operation. `fh` will contain the value set by the open method, or
    /// will be undefined if the open method didn't set any value.
    /// The method should return `Ok(u32)` with the number of bytes written, or `Err(Errno)` otherwise.
    ///
    /// `write_flags`: will contain `FUSE_WRITE_CACHE`, if this write is from the page cache. If set,
    /// the pid, uid, gid, and fh may not match the value that would have been sent if write caching
    /// is disabled.
    /// `flags`: these are the file flags, such as `O_SYNC`. Only supported with ABI >= 7.9.
    /// `lock_owner`: only supported with ABI >= 7.9.
    fn write(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
    ) -> Result<u32, Errno> {
        warn!(
            "[Not Implemented] write(ino: {:#x?}, fh: {}, offset: {}, data.len(): {}, \
            write_flags: {:#x?}, flags: {:#x?}, lock_owner: {:?})",
            ino,
            fh,
            offset,
            data.len(),
            write_flags,
            flags,
            lock_owner
        );
        Err(Errno::ENOSYS)
    }

    /// Flush method.
    /// This is called on each `close()` of the opened file. Since file descriptors can
    /// be duplicated (dup, dup2, fork), for one open call there may be many flush
    /// calls. Filesystems shouldn't assume that flush will always be called after some
    /// writes, or that it will be called at all. `fh` will contain the value set by the
    /// open method, or will be undefined if the open method didn't set any value.
    /// NOTE: the name of the method is misleading, since (unlike fsync) the filesystem
    /// is not forced to flush pending writes. One reason to flush data is if the
    /// filesystem wants to return write errors. If the filesystem supports file locking
    /// operations (setlk, getlk) it should remove all locks belonging to `lock_owner`.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn flush(&mut self, req: RequestMeta, ino: u64, fh: u64, lock_owner: u64) -> Result<(), Errno> {
        warn!("[Not Implemented] flush(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner:?})");
        Err(Errno::ENOSYS)
    }

    /// Release an open file.
    /// Release is called when there are no more references to an open file: all file
    /// descriptors are closed and all memory mappings are unmapped. For every open
    /// call there will be exactly one release call. The filesystem may return an
    /// error, but error values are not returned to `close()` or `munmap()` which triggered
    /// the release. `fh` will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value. `flags` will contain the same flags as for
    /// open.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn release(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
    ) -> Result<(), Errno> {
        Ok(())
    }

    /// Synchronize file contents.
    /// If the `datasync` parameter is non-zero, then only the user data should be flushed,
    /// not the meta data.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn fsync(&mut self, req: RequestMeta, ino: u64, fh: u64, datasync: bool) -> Result<(), Errno> {
        warn!("[Not Implemented] fsync(ino: {ino:#x?}, fh: {fh}, datasync: {datasync})");
        Err(Errno::ENOSYS)
    }

    /// Open a directory.
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in `Open.fh`, and
    /// use this in other all other directory stream operations (readdir, releasedir,
    /// fsyncdir). Filesystem may also implement stateless directory I/O and not store
    /// anything in `Open.fh`, though that makes it impossible to implement standard conforming
    /// directory stream operations in case the contents of the directory can change
    /// between opendir and releasedir.
    /// The method should return `Ok(Open)` on success, or `Err(Errno)` otherwise.
    fn opendir(&mut self, req: RequestMeta, ino: u64, flags: i32) -> Result<Open, Errno> {
        warn!("[Not Implemented] open(ino: {ino:#x?}, flags: {flags})");
        Err(Errno::ENOSYS)
        // TODO: maybe Open{0, 0} instead?
    }

    /// Read directory.
    /// The filesystem should return a list of directory entries.
    /// A buffer will be filled with entries from up to `max_bytes`.
    /// An empty list indicates the end of the stream.
    /// `fh` will contain the value set by the opendir method, or will be undefined if the
    /// opendir method didn't set any value.
    fn readdir<'dir, 'name>(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        offset: i64,
        max_bytes: u32
    ) -> Result<DirentList<'dir, 'name>, Errno> {
        warn!("[Not Implemented] readdir(ino: {ino:#x?}, fh: {fh}, offset: {offset}, max_bytes: {max_bytes})");
        Err(Errno::ENOSYS)
    }

    /// Read directory.
    /// Similar to `readdir`, but also returns the attributes of each directory entry.
    /// The filesystem should return a list of tuples of directory entries and their attributes.
    /// A buffer will be filled with entries and attributes up to `max_bytes`.
    /// An empty list indicates the end of the stream.
    /// `fh` will contain the value set by the opendir method, or will be
    /// undefined if the opendir method didn't set any value.
    #[cfg(feature = "abi-7-21")]
    fn readdirplus<'dir, 'name>(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        offset: i64,
        max_bytes: u32,
    ) -> Result<DirentPlusList<'dir, 'name>, Errno> {
        warn!(
            "[Not Implemented] readdirplus(ino: {ino:#x?}, fh: {fh}, \
            offset: {offset}, max_bytes: {max_bytes})"
        );
        Err(Errno::ENOSYS)
    }

    /// Release an open directory.
    /// For every opendir call there will be exactly one releasedir call. `fh` will
    /// contain the value set by the opendir method, or will be undefined if the
    /// opendir method didn't set any value.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn releasedir(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        flags: i32,
    ) -> Result<(), Errno> {
        Ok(())
    }

    /// Synchronize directory contents.
    /// If the `datasync` parameter is set, then only the directory contents should
    /// be flushed, not the meta data. `fh` will contain the value set by the opendir
    /// method, or will be undefined if the opendir method didn't set any value.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn fsyncdir(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        datasync: bool,
    ) -> Result<(), Errno> {
        warn!("[Not Implemented] fsyncdir(ino: {ino:#x?}, fh: {fh}, datasync: {datasync})");
        Err(Errno::ENOSYS)
    }

    /// Get file system statistics.
    /// The method should return `Ok(Statfs)` with the filesystem statistics, or `Err(Errno)` otherwise.
    fn statfs(&mut self, req: RequestMeta, ino: u64) -> Result<Statfs, Errno> {
        warn!("[Not Implemented] statfs(ino: {ino:#x?})");
        Err(Errno::ENOSYS)
        // TODO: Statfs{0, 0, 0, 0, 0, 512, 255, 0}
    }

    /// Set an extended attribute.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn setxattr(
        &mut self,
        req: RequestMeta,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
    ) -> Result<(), Errno> {
        warn!("[Not Implemented] setxattr(ino: {ino:#x?}, name: {name:?}, flags: {flags:#x?}, position: {position})");
        Err(Errno::ENOSYS)
    }

    /// Get an extended attribute.
    /// If `size` is 0, the size of the value should be returned in `Xattr::Size(u32)`.
    /// If `size` is not 0, and the value fits, the value should be returned in `Xattr::Data(Bytes<'a>)`.
    /// `Bytes` allows for returning borrowed or owned data for the attribute value.
    /// If the value does not fit, `Err(Errno::ERANGE)` should be returned.
    /// The method should return `Ok(Xattr<'a>)` on success, or `Err(Errno)` otherwise.
    fn getxattr<'a>(
        &mut self,
        req: RequestMeta,
        ino: u64,
        name: &OsStr,
        size: u32,
    ) -> Result<Xattr<'a>, Errno> {
        warn!("[Not Implemented] getxattr(ino: {ino:#x?}, name: {name:?}, size: {size})");
        Err(Errno::ENOSYS)
    }

    /// List extended attribute names.
    /// If `size` is 0, the size of the names list should be returned in `Xattr::Size(u32)`.
    /// If `size` is not 0, and the names list fits, it should be returned in `Xattr::Data(ByteBox<'a>)`.
    /// `ByteBox` allows for returning borrowed or owned data for the concatenated list of names.
    /// If the list does not fit, `Err(Errno::ERANGE)` should be returned.
    /// The method should return `Ok(Xattr<'a>)` on success, or `Err(Errno)` otherwise.
    fn listxattr<'a>(
        &mut self,
        req: RequestMeta,
        ino: u64,
        size: u32,
    ) -> Result<Xattr<'a>, Errno> {
        warn!("[Not Implemented] listxattr(ino: {ino:#x?}, size: {size})");
        Err(Errno::ENOSYS)
    }

    /// Remove an extended attribute.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn removexattr(
        &mut self,
        req: RequestMeta,
        ino: u64,
        name: &OsStr,
    ) -> Result<(), Errno> {
        warn!("[Not Implemented] removexattr(ino: {ino:#x?}, name: {name:?})");
        Err(Errno::ENOSYS)
    }

    /// Check file access permissions.
    /// This will be called for the `access()` system call. If the '`default_permissions`'
    /// mount option is given, this method is not called. This method is not called
    /// under Linux kernel versions 2.4.x
    /// The method should return `Ok(())` if access is allowed, or `Err(Errno)` otherwise.
    fn access(&mut self, req: RequestMeta, ino: u64, mask: i32) -> Result<(), Errno> {
        warn!("[Not Implemented] access(ino: {ino:#x?}, mask: {mask})");
        Err(Errno::ENOSYS)
    }

    /// Create and open a file.
    /// If the file does not exist, first create it with the specified mode, and then
    /// open it. You can use any open flags in the `flags` parameter except `O_NOCTTY`.
    /// The filesystem can store any type of file handle (such as a pointer or index)
    /// in `Open.fh`, which can then be used across all subsequent file operations including
    /// read, write, flush, release, and fsync. Additionally, the filesystem may set
    /// certain flags like `direct_io` and `keep_cache` in `Open.flags` to change the way the file is
    /// opened. See `fuse_file_info` structure in `<fuse_common.h>` for more details. If
    /// this method is not implemented or under Linux kernel versions earlier than
    /// 2.6.15, the `mknod()` and `open()` methods will be called instead.
    /// The method should return `Ok((Entry, Open))` with the new entry's attributes and open file information, or `Err(Errno)` otherwise.
    fn create(
        &mut self,
        req: RequestMeta,
        parent: u64,
        name: &Path,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Result<(Entry,Open), Errno> {
        warn!(
            "[Not Implemented] create(parent: {parent:#x?}, name: {name:?}, \
            mode: {mode}, umask: {umask:#x?}, flags: {flags:#x?})"
        );
        Err(Errno::ENOSYS)
    }

    /// Test for a POSIX file lock.
    /// The method should return `Ok(Lock)` with the lock information, or `Err(Errno)` otherwise.
    fn getlk(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
    ) -> Result<Lock, Errno> {
        warn!(
            "[Not Implemented] getlk(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner}, \
            start: {start}, end: {end}, typ: {typ}, pid: {pid})"
        );
        Err(Errno::ENOSYS)
    }

    /// Acquire, modify or release a POSIX file lock.
    /// For POSIX threads (NPTL) there's a 1-1 relation between `pid` and `owner`, but
    /// otherwise this is not always the case.  For checking lock ownership,
    /// `fi->owner` must be used. The `l_pid` field in `struct flock` should only be
    /// used to fill in this field in `getlk()`. Note: if the locking methods are not
    /// implemented, the kernel will still allow file locking to work locally.
    /// Hence these are only interesting for network filesystems and similar.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn setlk(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
    ) -> Result<(), Errno> {
        warn!(
            "[Not Implemented] setlk(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner}, \
            start: {start}, end: {end}, typ: {typ}, pid: {pid}, sleep: {sleep})"
        );
        Err(Errno::ENOSYS)
    }

    /// Map block index within file to block index within device.
    /// Note: This makes sense only for block device backed filesystems mounted
    /// with the 'blkdev' option.
    /// The method should return `Ok(u64)` with the device block index, or `Err(Errno)` otherwise.
    fn bmap(&mut self, req: RequestMeta, ino: u64, blocksize: u32, idx: u64) -> Result<u64, Errno> {
        warn!("[Not Implemented] bmap(ino: {ino:#x?}, blocksize: {blocksize}, idx: {idx})");
        Err(Errno::ENOSYS)
    }

    /// Control device.
    /// The method should return `Ok(Ioctl)` with the ioctl result, or `Err(Errno)` otherwise.
    #[cfg(feature = "abi-7-11")]
    fn ioctl<'a>(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        fh: u64,
        flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
    ) -> Result<Ioctl<'a>, Errno> {
        warn!(
            "[Not Implemented] ioctl(ino: {:#x?}, fh: {}, flags: {}, cmd: {}, \
            in_data.len(): {}, out_size: {})",
            ino,
            fh,
            flags,
            cmd,
            in_data.len(),
            out_size,
        );
        Err(Errno::ENOSYS)
    }

    /// Poll for events.
    /// The method should return `Ok(u32)` with the poll events, or `Err(Errno)` otherwise.
    /// Ok(nonzero) indicates that the file is ready now.
    /// Ok(0) indicates that the file is not ready. In that case,
    /// the filesystem should save the poll handle (`ph`) in its internal structure.
    /// Later events should be sent via the notification channel.
    #[cfg(feature = "abi-7-11")]
    fn poll(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        ph: u64,
        events: u32,
        flags: u32,
    ) -> Result<u32, Errno> {
        warn!(
            "[Not Implemented] poll(ino: {ino:#x?}, fh: {fh}, \
            ph: {ph:?}, events: {events}, flags: {flags})"
        );
        Err(Errno::ENOSYS)
    }

    /// Initializes the notification event sender for the filesystem.
    /// The boolean indicates whether the filesystem supports it.
    #[cfg(feature = "abi-7-11")]
    fn init_notification_sender(
        &mut self,
        _sender: crossbeam_channel::Sender<Notification>,
    ) -> bool {
        false // Default: not supported
    }

    /// In a syncronous execution model where a sleep may happen,
    /// the heartbeat may be used to alert the Filesystem that time has passed.
    fn heartbeat(&mut self) -> Result<FsStatus, Errno> {
        Ok(FsStatus::Default)
    }

    /// Preallocate or deallocate space to a file.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    fn fallocate(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
    ) -> Result<(), Errno> {
        warn!(
            "[Not Implemented] fallocate(ino: {ino:#x?}, fh: {fh}, offset: {offset}, \
            length: {length}, mode: {mode})"
        );
        Err(Errno::ENOSYS)
    }

    /// Reposition read/write file offset.
    /// The method should return `Ok(i64)` with the new offset, or `Err(Errno)` otherwise.
    #[cfg(feature = "abi-7-24")]
    fn lseek(
        &mut self,
        req: RequestMeta,
        ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
    ) -> Result<i64, Errno> {
        warn!("[Not Implemented] lseek(ino: {ino:#x?}, fh: {fh}, offset: {offset}, whence: {whence})");
        Err(Errno::ENOSYS)
    }

    /// Copy the specified range from the source inode to the destination inode.
    /// The method should return `Ok(u32)` with the number of bytes copied, or `Err(Errno)` otherwise.
    fn copy_file_range(
        &mut self,
        req: RequestMeta,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
    ) -> Result<u32, Errno> {
        warn!(
            "[Not Implemented] copy_file_range(ino_in: {ino_in:#x?}, fh_in: {fh_in}, \
            offset_in: {offset_in}, ino_out: {ino_out:#x?}, fh_out: {fh_out}, \
            offset_out: {offset_out}, len: {len}, flags: {flags})"
        );
        Err(Errno::ENOSYS)
    }

    /// macOS only: Rename the volume. Set `fuse_init_out.flags` during init to
    /// `FUSE_VOL_RENAME` to enable.
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    #[cfg(target_os = "macos")]
    fn setvolname(&mut self, req: RequestMeta, name: &OsStr) -> Result<(), Errno> {
        warn!("[Not Implemented] setvolname(name: {name:?})");
        Err(Errno::ENOSYS)
    }

    /// macOS only (undocumented).
    /// The method should return `Ok(())` on success, or `Err(Errno)` otherwise.
    #[cfg(target_os = "macos")]
    fn exchange(
        &mut self,
        req: RequestMeta,
        parent: u64,
        name: &Path,
        newparent: u64,
        newname: &Path,
        options: u64
    ) -> Result<(), Errno> {
        warn!(
            "[Not Implemented] exchange(parent: {parent:#x?}, name: {name:?}, \
            newparent: {newparent:#x?}, newname: {newname:?}, options: {options:?})"
        );
        Err(Errno::ENOSYS)
    }

    /// macOS only: Query extended times (bkuptime and crtime). Set `fuse_init_out.flags`
    /// during init to `FUSE_XTIMES` to enable.
    /// The method should return `Ok(XTimes)` with the extended times, or `Err(Errno)` otherwise.
    #[cfg(target_os = "macos")]
    fn getxtimes(&mut self, req: RequestMeta, ino: u64) -> Result<XTimes, Errno> {
        warn!("[Not Implemented] getxtimes(ino: {ino:#x?})");
        Err(Errno::ENOSYS)
    }
}

/// Mount the given filesystem to the given mountpoint. This function will
/// block until the filesystem is unmounted.
///
/// `filesystem`: The filesystem implementation.
/// `mountpoint`: The path to the mountpoint.
/// `options`: A slice of mount options. Each option needs to be a separate string,
/// typically starting with `"-o"`. For example: `&[OsStr::new("-o"), OsStr::new("auto_unmount")]`.
/// # Errors
/// Error if the mount does not succeed.
#[deprecated(note = "Use `mount2` instead, which takes a slice of `MountOption` enums for better type safety and clarity.")]
pub fn mount<FS: Filesystem, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &[&OsStr],
) -> io::Result<()> {
    let options = parse_options_from_args(options)?;
    mount2(filesystem, mountpoint, options.as_ref())
}

/// Mount the given filesystem to the given mountpoint. This function will
/// block until the filesystem is unmounted.
///
/// `filesystem`: The filesystem implementation.
/// `mountpoint`: The path to the mountpoint.
/// `options`: A slice of `MountOption` enums specifying mount options.
///
/// This is the recommended way to mount a FUSE filesystem.
/// # Errors
/// Error if the mount does not succeed.
pub fn mount2<FS: Filesystem, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &[MountOption],
) -> io::Result<()> {
    check_option_conflicts(options)?;
    Session::new(filesystem, mountpoint.as_ref(), options).and_then(|mut se| se.run())
}

/// Mount the given filesystem to the given mountpoint in a background thread.
/// This function spawns a new thread to handle filesystem operations and returns
/// immediately. The returned `BackgroundSession` handle should be stored to
/// keep the filesystem mounted. When the handle is dropped, the filesystem will
/// be unmounted.
///
/// `filesystem`: The filesystem implementation. Must be `Send + 'static`.
/// `mountpoint`: The path to the mountpoint.
/// `options`: A slice of mount options. Each option needs to be a separate string,
/// typically starting with `"-o"`. For example: `&[OsStr::new("-o"), OsStr::new("auto_unmount")]`.
/// # Errors
/// Error if the session is not started.
#[deprecated(note = "Use `spawn_mount2` instead, which takes a slice of `MountOption` enums for better type safety and clarity.")]
pub fn spawn_mount<'a, FS: Filesystem + Send + 'static + 'a, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &[&OsStr],
) -> io::Result<BackgroundSession> {
    let options: Option<Vec<_>> = options
        .iter()
        .map(|x| Some(MountOption::from_str(x.to_str()?)))
        .collect();
    let options = options.ok_or(ErrorKind::InvalidData)?;
    Session::new(filesystem, mountpoint.as_ref(), options.as_ref()).and_then(session::Session::spawn)
}

/// Mount the given filesystem to the given mountpoint in a background thread.
/// This function spawns a new thread to handle filesystem operations and returns
/// immediately. The returned `BackgroundSession` handle should be stored to
/// keep the filesystem mounted. When the handle is dropped, the filesystem will
/// be unmounted.
///
/// `filesystem`: The filesystem implementation. Must be `Send + 'static`.
/// `mountpoint`: The path to the mountpoint.
/// `options`: A slice of `MountOption` enums specifying mount options.
///
/// This is the recommended way to mount a FUSE filesystem in the background.
/// # Errors
/// Error if the session is not started.
pub fn spawn_mount2<'a, FS: Filesystem + Send + 'static + 'a, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &[MountOption],
) -> io::Result<BackgroundSession> {
    check_option_conflicts(options)?;
    Session::new(filesystem, mountpoint.as_ref(), options).and_then(session::Session::spawn)
}
