//! FUSE userspace library implementation
//!
//! This is an improved rewrite of the FUSE userspace library (lowlevel interface) to fully take
//! advantage of Rust's architecture. The only thing we rely on in the real libfuse are mount
//! and unmount calls which are needed to establish a fd to talk to the kernel driver.

#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub
)]

use std::cmp::max;
use std::cmp::min;
use std::convert::AsRef;
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;

use log::warn;
#[cfg(target_os = "macos")]
pub use reply::ReplyXTimes;
#[cfg(feature = "serializable")]
use serde::Deserialize;
#[cfg(feature = "serializable")]
use serde::Serialize;

pub use crate::access_flags::AccessFlags;
pub use crate::bsd_file_flags::BsdFileFlags;
use crate::forget_one::ForgetOne;
pub use crate::ll::Errno;
pub use crate::ll::Generation;
pub use crate::ll::RequestId;
pub use crate::ll::TimeOrNow;
pub use crate::ll::flags::copy_file_range_flags::CopyFileRangeFlags;
pub use crate::ll::flags::fopen_flags::FopenFlags;
pub use crate::ll::flags::init_flags::InitFlags;
pub use crate::ll::flags::ioctl_flags::IoctlFlags;
pub use crate::ll::flags::poll_flags::PollFlags;
pub use crate::ll::flags::statx_flags::StatxAttributes;
pub use crate::ll::flags::statx_flags::StatxMask;
pub use crate::ll::flags::write_flags::WriteFlags;
pub use crate::ll::fuse_abi::consts;
pub use crate::ll::request::FileHandle;
pub use crate::ll::request::INodeNo;
pub use crate::ll::request::LockOwner;
pub use crate::ll::request::Version;
pub use crate::mnt::mount_options::Config;
pub use crate::mnt::mount_options::MountOption;
pub use crate::notify::Notifier;
pub use crate::notify::PollHandle;
pub use crate::notify::PollNotifier;
pub use crate::open_flags::OpenAccMode;
pub use crate::open_flags::OpenFlags;
pub use crate::passthrough::BackingId;
pub use crate::poll_events::PollEvents;
pub use crate::rename_flags::RenameFlags;
pub use crate::reply::ReplyAttr;
pub use crate::reply::ReplyBmap;
pub use crate::reply::ReplyCreate;
pub use crate::reply::ReplyData;
pub use crate::reply::ReplyDirectory;
pub use crate::reply::ReplyDirectoryPlus;
pub use crate::reply::ReplyEmpty;
pub use crate::reply::ReplyEntry;
pub use crate::reply::ReplyIoctl;
pub use crate::reply::ReplyLock;
pub use crate::reply::ReplyLseek;
pub use crate::reply::ReplyOpen;
pub use crate::reply::ReplyPoll;
pub use crate::reply::ReplyStatfs;
pub use crate::reply::ReplyStatx;
pub use crate::reply::ReplyWrite;
pub use crate::reply::ReplyXattr;
pub use crate::request_param::Request;
pub use crate::session::BackgroundSession;
use crate::session::MAX_WRITE_SIZE;
use crate::session::MIN_WRITE_SIZE;
pub use crate::session::Session;
pub use crate::session::SessionACL;
pub use crate::session::SessionUnmounter;

mod access_flags;
mod bsd_file_flags;
mod channel;
mod dev_fuse;
/// Experimental APIs
#[cfg(feature = "experimental")]
pub mod experimental;
mod forget_one;
mod ll;
mod mnt;
mod notify;
mod open_flags;
mod passthrough;
mod poll_events;
mod read_buf;
mod rename_flags;
mod reply;
mod request;
mod request_param;
mod session;
mod time;

/// We generally support async reads
#[cfg(not(target_os = "macos"))]
const INIT_FLAGS: InitFlags = InitFlags::FUSE_ASYNC_READ.union(InitFlags::FUSE_BIG_WRITES);
// TODO: Add FUSE_EXPORT_SUPPORT

/// On macOS, we additionally support volume renames, xtimes and the extended rename
/// operations. A filesystem that is case-insensitive requests
/// `InitFlags::FUSE_CASE_INSENSITIVE` itself.
///
/// `FUSE_RENAME_SWAP`/`FUSE_RENAME_EXCL` are requested so that `renamex_np(2)` flags reach
/// `rename()`.
/// TODO: we should eventually let the filesystem implementation decide which flags to set
#[cfg(target_os = "macos")]
const INIT_FLAGS: InitFlags = InitFlags::FUSE_ASYNC_READ
    .union(InitFlags::FUSE_VOL_RENAME)
    .union(InitFlags::FUSE_XTIMES)
    .union(InitFlags::FUSE_RENAME_SWAP)
    .union(InitFlags::FUSE_RENAME_EXCL);
// TODO: Add FUSE_EXPORT_SUPPORT and FUSE_BIG_WRITES (requires ABI 7.10)

#[cfg_attr(target_os = "macos", expect(unused_variables))]
fn default_init_flags(capabilities: InitFlags) -> InitFlags {
    #[cfg_attr(target_os = "macos", expect(unused_mut))]
    let mut flags = INIT_FLAGS;
    #[cfg(not(target_os = "macos"))]
    if capabilities.contains(InitFlags::FUSE_MAX_PAGES) {
        flags |= InitFlags::FUSE_MAX_PAGES;
    }
    flags
}

/// What the kernel puts in a request header in place of ids it is not sending.
pub(crate) const FUSE_INVALID_UIDGID: u32 = u32::MAX;

/// Capabilities fuser has no implementation behind, whatever the kernel advertises.
///
/// Negotiating one of these makes the kernel change the protocol in a way fuser gets wrong, or
/// claims a feature fuser cannot provide. Since the negotiated set is only ever echoed back to
/// the kernel, an unimplemented capability fails silently rather than loudly, so
/// [`KernelConfig::add_capabilities`] refuses them up front.
///
/// macFUSE has none of these capabilities, so nothing is refused on macOS.
#[cfg(not(target_os = "macos"))]
const UNSUPPORTED_CAPABILITIES: InitFlags = InitFlags::empty()
    // Marking a submount root needs FUSE_ATTR_SUBMOUNT in the flags field of fuse_attr, which
    // fuser sends as padding. Only a transport with submounts (virtiofs) advertises this
    .union(InitFlags::FUSE_SUBMOUNTS)
    // Read from a fuse_init_out field fuser leaves zeroed, which makes the kernel refuse the
    // connection unless that happens to match its DAX alignment. Advertised by virtiofs alone
    .union(InitFlags::FUSE_MAP_ALIGNMENT)
    // The kernel appends a fuse_secctx_header extension after the name of a create, mkdir,
    // symlink or mknod request. fuser stops parsing at the name, so the security context is
    // dropped and the filesystem creates unlabeled files while believing it labels them
    .union(InitFlags::FUSE_SECURITY_CTX)
    // Likewise for the fuse_supp_groups extension. Dropping it leaves the filesystem with the
    // caller's fsgid in exactly the case the extension exists to correct
    .union(InitFlags::FUSE_CREATE_SUPP_GROUP)
    // Selecting DAX per inode requires FUSE_ATTR_DAX in the flags field of fuse_attr, which
    // fuser sends as padding. Only a DAX-capable transport (virtiofs) advertises this
    .union(InitFlags::FUSE_HAS_INODE_DAX)
    // The kernel would route requests to io_uring queues that fuser never creates
    .union(InitFlags::FUSE_OVER_IO_URING)
    // Announces that the filesystem copes with requests the kernel resends. fuser cannot send
    // the FUSE_NOTIFY_RESEND notification that asks for a resend in the first place
    .union(InitFlags::FUSE_HAS_RESEND);
#[cfg(target_os = "macos")]
const UNSUPPORTED_CAPABILITIES: InitFlags = InitFlags::empty();

/// Who a newly created inode belongs to.
///
/// The kernel decides this rather than the filesystem, and on an idmapped mount it is not the
/// same as the caller's ids: it is those ids mapped through the mount's idmapping. It is given
/// to the requests that create an inode, and to no others, which is why it is an argument to
/// those rather than something [`Request`] carries. A rename is one of them only with
/// `RENAME_WHITEOUT`, so it takes an `Option<Owner>` which is `Some` for exactly that flag.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Owner {
    /// Owning user
    pub uid: u32,
    /// Owning group, before any setgid inheritance the filesystem applies
    pub gid: u32,
}

/// File types
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serializable", derive(Serialize, Deserialize))]
pub enum FileType {
    /// Named pipe (`S_IFIFO`)
    NamedPipe,
    /// Character device (`S_IFCHR`)
    CharDevice,
    /// Block device (`S_IFBLK`)
    BlockDevice,
    /// Directory (`S_IFDIR`)
    Directory,
    /// Regular file (`S_IFREG`)
    RegularFile,
    /// Symbolic link (`S_IFLNK`)
    Symlink,
    /// Unix domain socket (`S_IFSOCK`)
    Socket,
}

impl FileType {
    /// Convert std `FileType` to fuser `FileType`.
    pub fn from_std(file_type: std::fs::FileType) -> Option<Self> {
        if file_type.is_file() {
            Some(FileType::RegularFile)
        } else if file_type.is_dir() {
            Some(FileType::Directory)
        } else if file_type.is_symlink() {
            Some(FileType::Symlink)
        } else if file_type.is_fifo() {
            Some(FileType::NamedPipe)
        } else if file_type.is_socket() {
            Some(FileType::Socket)
        } else if file_type.is_char_device() {
            Some(FileType::CharDevice)
        } else if file_type.is_block_device() {
            Some(FileType::BlockDevice)
        } else {
            None
        }
    }
}

/// File attributes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serializable", derive(Serialize, Deserialize))]
pub struct FileAttr {
    /// Inode number
    pub ino: INodeNo,
    /// Size in bytes
    pub size: u64,
    /// Allocated size in 512-byte blocks. May be smaller than the actual file size
    /// if the file is compressed, for example.
    pub blocks: u64,
    /// Time of last access
    pub atime: SystemTime,
    /// Time of last modification
    pub mtime: SystemTime,
    /// Time of last change
    pub ctime: SystemTime,
    /// Time of creation (macOS only)
    pub crtime: SystemTime,
    /// Kind of file (directory, file, pipe, etc)
    pub kind: FileType,
    /// Permissions
    pub perm: u16,
    /// Number of hard links
    pub nlink: u32,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
    /// Rdev
    pub rdev: u32,
    /// Block size to be reported by `stat()`. If unsure, set to 4096.
    pub blksize: u32,
    /// Flags (macOS only, see chflags(2))
    pub flags: u32,
}

/// What `statx(2)` reports, which is [`FileAttr`] plus the fields `stat(2)` has no room for.
///
/// In practice that means [`btime`](Self::btime): a creation time, which `FUSE_GETATTR` has
/// no field for on Linux and which no other request can carry.
#[derive(Debug, Clone, Copy)]
pub struct StatxAttr {
    /// Everything `stat(2)` also reports
    pub attr: FileAttr,
    /// Time of creation, reported to the caller only when this is `Some`. Unlike
    /// [`FileAttr::crtime`] this is not macOS-only, since `statx(2)` has a field for it
    pub btime: Option<SystemTime>,
    /// Properties of the file that are set, such as immutable or append-only.
    ///
    /// **The kernel discards this.** `fuse_do_statx()` takes the mask, the creation time and
    /// the basic stats out of the reply and ignores the attributes, so nothing set here
    /// reaches `statx(2)`, and `chattr +i` cannot be made visible to it this way. The field
    /// is part of the wire format and is sent regardless, so a filesystem that fills it needs
    /// no change should the kernel start reading it.
    pub attributes: StatxAttributes,
    /// Properties this filesystem knows about at all, set or not, distinguishing "not set"
    /// from "cannot say".
    ///
    /// Discarded by the kernel for the same reason as [`attributes`](Self::attributes).
    pub attributes_mask: StatxAttributes,
}

impl From<FileAttr> for StatxAttr {
    /// Reports what `stat(2)` would, and nothing beyond it
    fn from(attr: FileAttr) -> Self {
        Self {
            attr,
            btime: None,
            attributes: StatxAttributes::empty(),
            attributes_mask: StatxAttributes::empty(),
        }
    }
}

impl TryFrom<&std::fs::Metadata> for FileAttr {
    type Error = io::Error;

    /// Convert the metadata of a local file, as returned by [`std::fs::metadata`] and friends.
    ///
    /// This suits a filesystem backed by files on disk, which can answer `getattr` and `lookup
    /// ` largely by passing the underlying file's metadata through. Note that `ino` is the
    /// inode number of that underlying file, which a filesystem assigning its own inode
    /// numbers will want to overwrite.
    ///
    /// `flags` carries the BSD file flags on macOS, where the FUSE protocol has a field for
    /// them, and is zero everywhere else. `crtime` falls back to the epoch on a platform or
    /// filesystem that does not record a creation time. `rdev` is taken from the metadata
    /// only for a character or block device, being unspecified for every other kind of file,
    /// and is zero otherwise.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidData`] if the file is of a kind [`FileType`] cannot
    /// represent, or if a field does not fit the width the FUSE protocol gives it. The latter
    /// needs a filesystem well outside what Linux itself can represent, since the kernel reads
    /// these back into the same widths.
    fn try_from(metadata: &std::fs::Metadata) -> Result<Self, Self::Error> {
        use std::os::unix::fs::MetadataExt;

        fn narrow(value: u64, field: &str) -> io::Result<u32> {
            u32::try_from(value).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{field} is {value}, which does not fit the FUSE protocol's u32"),
                )
            })
        }

        let kind = FileType::from_std(metadata.file_type()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported file type {:?}", metadata.file_type()),
            )
        })?;

        Ok(FileAttr {
            ino: INodeNo(metadata.ino()),
            size: metadata.size(),
            blocks: metadata.blocks(),
            atime: time::system_time_from_time(metadata.atime(), metadata.atime_nsec() as u32),
            mtime: time::system_time_from_time(metadata.mtime(), metadata.mtime_nsec() as u32),
            ctime: time::system_time_from_time(metadata.ctime(), metadata.ctime_nsec() as u32),
            crtime: metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
            kind,
            perm: (metadata.mode() & 0o7777) as u16,
            nlink: narrow(metadata.nlink(), "nlink")?,
            uid: metadata.uid(),
            gid: metadata.gid(),
            // `st_rdev` is only defined for device files, and reading it elsewhere gets
            // whatever the filesystem left there: FreeBSD's UFS stores a fast symlink's
            // target in the same inode field, so a symlink reports the first eight bytes
            // of its target as an rdev
            rdev: match kind {
                FileType::CharDevice | FileType::BlockDevice => narrow(metadata.rdev(), "rdev")?,
                _ => 0,
            },
            blksize: narrow(metadata.blksize(), "blksize")?,
            #[cfg(target_os = "macos")]
            flags: std::os::macos::fs::MetadataExt::st_flags(metadata),
            #[cfg(not(target_os = "macos"))]
            flags: 0,
        })
    }
}

/// Configuration of the fuse kernel module connection
#[derive(Debug)]
pub struct KernelConfig {
    capabilities: InitFlags,
    requested: InitFlags,
    max_readahead: u32,
    max_max_readahead: u32,
    max_background: u16,
    congestion_threshold: Option<u16>,
    max_write: u32,
    time_gran: Duration,
    max_stack_depth: u32,
    /// Seconds, 0 for none. Linux only
    #[cfg_attr(target_os = "macos", expect(dead_code))]
    request_timeout: u16,
    kernel_abi: Version,
    /// Whether the mount carries `MountOption::DefaultPermissions`, which
    /// `InitFlags::FUSE_ALLOW_IDMAP` cannot be negotiated without. Linux only
    #[cfg_attr(target_os = "macos", expect(dead_code))]
    default_permissions: bool,
    /// The session's ACL, for the same reason
    #[cfg_attr(target_os = "macos", expect(dead_code))]
    acl: SessionACL,
}

impl KernelConfig {
    fn new(
        capabilities: InitFlags,
        max_readahead: u32,
        kernel_abi: Version,
        default_permissions: bool,
        acl: SessionACL,
    ) -> Self {
        Self {
            capabilities,
            requested: default_init_flags(capabilities),
            max_readahead,
            max_max_readahead: max_readahead,
            max_background: 16,
            congestion_threshold: None,
            // use a max write size that fits into the session's buffer
            max_write: MAX_WRITE_SIZE as u32,
            // 1ns means nano-second granularity.
            time_gran: Duration::new(0, 1),
            max_stack_depth: 0,
            request_timeout: 0,
            kernel_abi,
            default_permissions,
            acl,
        }
    }

    /// Whether `InitFlags::FUSE_ALLOW_IDMAP` can be negotiated on this mount, given the
    /// capabilities being added alongside it.
    ///
    /// Two things have to hold, and neither is fuser's choice. The kernel needs something to
    /// check access against, since it withholds the caller's ids from the filesystem: it
    /// refuses the connection outright - every request answered `ECONNREFUSED` - unless
    /// `default_permissions` is in force. The mount option is one way to put it in force and
    /// `InitFlags::FUSE_POSIX_ACL` is the other, the kernel setting it from that flag before
    /// it looks at this one.
    ///
    /// And once the ids are withheld fuser cannot tell the mounting user's requests from
    /// anyone else's, so `SessionACL::Owner` and `SessionACL::RootAndOwner` could not be
    /// enforced; refusing is better than continuing to offer a restriction that has quietly
    /// stopped applying.
    #[cfg(not(target_os = "macos"))]
    fn idmap_available(&self, also_adding: InitFlags) -> bool {
        // Requesting POSIX ACLs only counts if the kernel offers them, since a capability it
        // does not offer is dropped from the negotiated set and sets nothing
        let acl_forces_default_permissions = (self.requested | also_adding)
            .intersection(self.capabilities)
            .contains(InitFlags::FUSE_POSIX_ACL);
        (self.default_permissions || acl_forces_default_permissions) && self.acl == SessionACL::All
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
    ///
    /// On success, returns the previous value.  
    /// # Errors
    /// If argument is too large, returns the nearest value which will succeed.
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

    /// Set how long the kernel waits for an answer to any request before it gives up on the
    /// filesystem. When a request goes unanswered for longer, the kernel aborts the connection:
    /// every pending and later request fails, as if the filesystem had died, and the session
    /// ends. [`Duration::ZERO`], the default, asks for no timeout.
    ///
    /// This needs `InitFlags::FUSE_REQUEST_TIMEOUT` from the kernel (Linux 6.14 and later),
    /// and is negotiated when a non-zero timeout is set. The kernel works in whole seconds and
    /// only checks for expired requests periodically (every 15 seconds on current kernels), so
    /// it raises a shorter timeout to that interval, and an expired request may wait up to an
    /// interval longer before the connection is aborted. The `fs.fuse.default_request_timeout`
    /// and `fs.fuse.max_request_timeout` sysctls can also apply a timeout or cap this one.
    ///
    /// On success returns the previous value.
    /// # Errors
    /// Returns the nearest value which will succeed: [`Duration::ZERO`] if the kernel does not
    /// support request timeouts, the next whole second for a fraction of a second, or the
    /// largest timeout the kernel accepts (`u16::MAX` seconds).
    #[cfg(not(target_os = "macos"))]
    pub fn set_request_timeout(&mut self, value: Duration) -> Result<Duration, Duration> {
        if value.is_zero() {
            let previous = Duration::from_secs(self.request_timeout.into());
            self.request_timeout = 0;
            self.requested.remove(InitFlags::FUSE_REQUEST_TIMEOUT);
            return Ok(previous);
        }
        if !self.capabilities.contains(InitFlags::FUSE_REQUEST_TIMEOUT) {
            return Err(Duration::ZERO);
        }
        if value.subsec_nanos() != 0 {
            return Err(Duration::from_secs(value.as_secs().saturating_add(1))
                .min(Duration::from_secs(u16::MAX.into())));
        }
        let Ok(seconds) = u16::try_from(value.as_secs()) else {
            return Err(Duration::from_secs(u16::MAX.into()));
        };
        let previous = Duration::from_secs(self.request_timeout.into());
        self.request_timeout = seconds;
        self.requested |= InitFlags::FUSE_REQUEST_TIMEOUT;
        Ok(previous)
    }

    /// Set the timestamp granularity
    ///
    /// Must be a power of 10 nanoseconds. i.e. 1s, 0.1s, 0.01s, 1ms, 0.1ms...etc
    ///
    /// On success returns the previous value.  
    /// # Errors
    /// If the argument does not match any valid granularity, returns the nearest value which will succeed.
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
    ///
    /// On success returns the previous value.
    /// # Errors
    /// If the argument is too small or too large, returns the nearest value which will succeed.
    pub fn set_max_write(&mut self, value: u32) -> Result<u32, u32> {
        // The kernel clamps max_write below 4096 up to 4096 (process_init_reply()
        // in fs/fuse/inode.c), so a smaller advertised value would not take
        // effect: write requests of up to 4096 bytes would still arrive
        if value < MIN_WRITE_SIZE as u32 {
            return Err(MIN_WRITE_SIZE as u32);
        }
        if value > MAX_WRITE_SIZE as u32 {
            return Err(MAX_WRITE_SIZE as u32);
        }
        let previous = self.max_write;
        self.max_write = value;
        Ok(previous)
    }

    /// Set the maximum readahead size
    ///
    /// On success returns the previous value.
    /// # Errors
    /// If the argument is too large, returns the nearest value which will succeed.
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

    /// Query kernel capabilities.
    pub fn capabilities(&self) -> InitFlags {
        #[cfg(not(target_os = "macos"))]
        return self.capabilities & !InitFlags::FUSE_INIT_EXT;
        #[cfg(target_os = "macos")]
        return self.capabilities;
    }

    /// Kernel ABI version.
    pub fn kernel_abi(&self) -> Version {
        self.kernel_abi
    }

    /// Add a set of capabilities.
    ///
    /// `InitFlags::FUSE_ALLOW_IDMAP` is accepted only where it can be honored: the session
    /// must allow other users, and `default_permissions` must be in force, whether from
    /// [`MountOption::DefaultPermissions`] or from negotiating `InitFlags::FUSE_POSIX_ACL`.
    /// Relying on the latter means adding it in this call or an earlier one, since what has
    /// not been asked for yet cannot be counted on.
    ///
    /// # Errors
    /// When the argument includes capabilities the kernel does not support, or ones fuser cannot
    /// honor, returns the bits of the capabilities that were refused. Nothing is added in that
    /// case, not even the capabilities that would have been accepted on their own.
    pub fn add_capabilities(&mut self, capabilities_to_add: InitFlags) -> Result<(), InitFlags> {
        #[cfg(not(target_os = "macos"))]
        let conditional = if self.idmap_available(capabilities_to_add) {
            InitFlags::empty()
        } else {
            InitFlags::FUSE_ALLOW_IDMAP
        };
        #[cfg(target_os = "macos")]
        let conditional = InitFlags::empty();
        let refused =
            capabilities_to_add & (!self.capabilities | UNSUPPORTED_CAPABILITIES | conditional);
        if !refused.is_empty() {
            return Err(refused);
        }
        self.requested |= capabilities_to_add;
        Ok(())
    }

    /// Set the maximum number of pending background requests. Such as readahead requests.
    ///
    /// On success returns the previous value.
    /// # Errors
    /// If the argument is too small, returns the nearest value which will succeed.
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
    ///
    /// On success returns the previous value.
    /// # Errors
    /// If the argument is too small, returns the nearest value which will succeed.
    pub fn set_congestion_threshold(&mut self, value: u16) -> Result<u16, u16> {
        if value == 0 {
            return Err(1);
        }
        let previous = self.congestion_threshold();
        self.congestion_threshold = Some(value);
        Ok(previous)
    }

    fn congestion_threshold(&self) -> u16 {
        match self.congestion_threshold {
            // Default to a threshold of 3/4 of the max background threads
            None => (u32::from(self.max_background) * 3 / 4) as u16,
            Some(value) => min(value, self.max_background),
        }
    }

    fn max_pages(&self) -> u16 {
        ((max(self.max_write, self.max_readahead) - 1) / page_size::get() as u32) as u16 + 1
    }
}

/// Filesystem trait.
///
/// This trait must be implemented to provide a userspace filesystem via FUSE.
/// These methods correspond to `fuse_lowlevel_ops` in libfuse. Reasonable default
/// implementations are provided here to get a mountable filesystem that does
/// nothing.
#[allow(clippy::too_many_arguments)]
pub trait Filesystem: Send + Sync + 'static {
    /// Initialize filesystem.
    /// Called before any other filesystem method.
    /// The kernel module connection can be configured using the `KernelConfig` object
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        Ok(())
    }

    /// Clean up filesystem.
    ///
    /// Called exactly once, as in libfuse. On a `fuseblk` mount (one mounted with `blkdev`), the
    /// kernel sends `FUSE_DESTROY` while unmounting and waits for the reply, which is sent once
    /// this returns: `umount` completes, and the block device is released, only after that, so
    /// writes made here reach the device first. Other mounts get no `FUSE_DESTROY`, and this is
    /// called when the session ends, after the connection is gone.
    ///
    /// No other method runs while it does or after it: it waits for requests being handled on
    /// other threads to return, and any the kernel still sends afterwards are answered with
    /// `EIO` without reaching the filesystem. Replies a method sends later from threads of its
    /// own are not waited for. It must not access the mountpoint, which is being unmounted.
    /// Cleanup that needs exclusive access to the filesystem can go in its `Drop`, which runs
    /// once the session has let go of it.
    fn destroy(&self) {}

    /// Look up a directory entry by name and get its attributes.
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        warn!("[Not Implemented] lookup(parent: {parent:#x?}, name {name:?})");
        reply.error(Errno::ENOSYS);
    }

    /// Forget about an inode.
    /// The nlookup parameter indicates the number of lookups previously performed on
    /// this inode. If the filesystem implements inode lifetimes, it is recommended that
    /// inodes acquire a single reference on each lookup, and lose nlookup references on
    /// each forget. The filesystem may ignore forget calls, if the inodes don't need to
    /// have a limited lifetime. On unmount it is not guaranteed, that all referenced
    /// inodes will receive a forget message.
    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {}

    /// Like [`forget`](Self::forget), but take multiple forget requests at once for performance. The default
    /// implementation will fallback to `forget`.
    fn batch_forget(&self, req: &Request, nodes: &[ForgetOne]) {
        for node in nodes {
            self.forget(req, node.nodeid(), node.nlookup());
        }
    }

    /// Get file attributes.
    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        warn!("[Not Implemented] getattr(ino: {ino:#x?}, fh: {fh:#x?})");
        reply.error(Errno::ENOSYS);
    }

    /// Get extended file attributes, for `statx(2)`.
    ///
    /// Answering this rather than leaving it to [`Filesystem::getattr`] lets a filesystem
    /// report a creation time, which no other request can carry: `fuse_attr` has a field for
    /// it on macOS alone, and `statx(2)` otherwise reports whatever the kernel last cached.
    ///
    /// It does not, despite the wire format having room for them, make the `STATX_ATTR_*`
    /// properties reportable - see [`StatxAttr::attributes`].
    ///
    /// `mask` is what the caller asked for. It is a request rather than an obligation:
    /// answering with more costs nothing, and what the reply actually carries is described by
    /// the reply itself.
    ///
    /// Answering `ENOSYS`, which is the default, is permanent: the kernel stops sending
    /// `FUSE_STATX` on this connection and serves `statx(2)` out of [`Filesystem::getattr`].
    fn statx(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Option<FileHandle>,
        flags: u32,
        mask: StatxMask,
        reply: ReplyStatx,
    ) {
        warn!(
            "[Not Implemented] statx(ino: {ino:#x?}, fh: {fh:#x?}, flags: {flags:#x?}, \
            mask: {mask:?})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Set file attributes.
    ///
    /// `kill_suid_gid` asks the filesystem to clear the suid and sgid bits of the file as part
    /// of this request, because the caller lacks `CAP_FSETID`. It is only ever set once
    /// `InitFlags::FUSE_HANDLE_KILLPRIV_V2` has been negotiated, since the kernel otherwise
    /// clears them itself.
    ///
    /// Honoring it is necessary but not sufficient: that capability also makes clearing the
    /// `security.capability` xattr on every write, chown and truncate the filesystem's job,
    /// and no argument reports that. See `InitFlags::FUSE_HANDLE_KILLPRIV_V2`.
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        warn!(
            "[Not Implemented] setattr(ino: {ino:#x?}, mode: {mode:?}, uid: {uid:?}, \
            gid: {gid:?}, size: {size:?}, fh: {fh:?}, flags: {flags:?}, \
            kill_suid_gid: {kill_suid_gid})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Read symbolic link.
    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        warn!("[Not Implemented] readlink(ino: {ino:#x?})");
        reply.error(Errno::ENOSYS);
    }

    /// Create file node.
    /// Create a regular file, character device, block device, fifo or socket node.
    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        warn!(
            "[Not Implemented] mknod(parent: {parent:#x?}, name: {name:?}, \
            mode: {mode}, umask: {umask:#x?}, rdev: {rdev})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Create a directory.
    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        warn!(
            "[Not Implemented] mkdir(parent: {parent:#x?}, name: {name:?}, mode: {mode}, umask: {umask:#x?})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Remove a file.
    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        warn!("[Not Implemented] unlink(parent: {parent:#x?}, name: {name:?})",);
        reply.error(Errno::ENOSYS);
    }

    /// Remove a directory.
    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        warn!("[Not Implemented] rmdir(parent: {parent:#x?}, name: {name:?})",);
        reply.error(Errno::ENOSYS);
    }

    /// Create a symbolic link.
    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        warn!(
            "[Not Implemented] symlink(parent: {parent:#x?}, link_name: {link_name:?}, target: {target:?})",
        );
        reply.error(Errno::EPERM);
    }

    /// Rename a file.
    ///
    /// `flags` are the `renameat2` flags on Linux and the `renamex_np` flags on macOS. Reply
    /// with EINVAL for any flag that isn't handled.
    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        _owner: Option<Owner>,
        reply: ReplyEmpty,
    ) {
        warn!(
            "[Not Implemented] rename(parent: {parent:#x?}, name: {name:?}, \
            newparent: {newparent:#x?}, newname: {newname:?}, flags: {flags})",
        );
        reply.error(Errno::ENOSYS);
    }

    /// Create a hard link.
    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        warn!(
            "[Not Implemented] link(ino: {ino:#x?}, newparent: {newparent:#x?}, newname: {newname:?})"
        );
        reply.error(Errno::EPERM);
    }

    /// Open a file.
    /// Open flags (with the exception of `O_CREAT`, `O_EXCL`, `O_NOCTTY` and `O_TRUNC`) are
    /// available in flags. Filesystem may store an arbitrary file handle (pointer, index,
    /// etc) in fh, and use this in other all other file operations (read, write, flush,
    /// release, fsync). Filesystem may also implement stateless file I/O and not store
    /// anything in fh. There are also some flags (`direct_io`, `keep_cache`) which the
    /// filesystem may set, to change the way the file is opened. See `fuse_file_info`
    /// structure in <`fuse_common.h`> for more details.
    ///
    /// `kill_suid_gid` asks the filesystem to clear the suid and sgid bits of the file, because
    /// the open truncates it and the caller lacks `CAP_FSETID`. It is only ever set once
    /// `InitFlags::FUSE_HANDLE_KILLPRIV_V2` has been negotiated, since the kernel otherwise
    /// clears them itself.
    ///
    /// Honoring it is necessary but not sufficient: that capability also makes clearing the
    /// `security.capability` xattr on every write, chown and truncate the filesystem's job,
    /// and no argument reports that. See `InitFlags::FUSE_HANDLE_KILLPRIV_V2`.
    ///
    /// Replying `ENOSYS` tells the kernel that opens need no answer: it stops sending them
    /// and treats every later open as successful. Opens then reach neither the filesystem
    /// nor the session's [`SessionACL`] check, so under [`SessionACL::RootAndOwner`] any user
    /// can read file data the kernel has cached.
    fn open(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    /// Read data.
    /// Read should send exactly the number of bytes requested except on EOF or error,
    /// otherwise the rest of the data will be substituted with zeroes. An exception to
    /// this is when the file has been opened in `direct_io` mode, in which case the
    /// return value of the read system call will reflect the return value of this
    /// operation. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value.
    ///
    /// flags: these are the file flags, such as `O_SYNC`. Only supported with ABI >= 7.9
    /// `lock_owner`: only supported with ABI >= 7.9
    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        warn!(
            "[Not Implemented] read(ino: {ino:#x?}, fh: {fh}, offset: {offset}, \
            size: {size}, flags: {flags:#x?}, lock_owner: {lock_owner:?})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Write data.
    /// Write should return exactly the number of bytes requested except on error. An
    /// exception to this is when the file has been opened in `direct_io` mode, in
    /// which case the return value of the write system call will reflect the return
    /// value of this operation. fh will contain the value set by the open method, or
    /// will be undefined if the open method didn't set any value.
    ///
    /// `write_flags`: will contain `FUSE_WRITE_CACHE`, if this write is from the page cache. If set,
    /// the pid, uid, gid, and fh may not match the value that would have been sent if write cachin
    /// is disabled
    /// flags: these are the file flags, such as `O_SYNC`. Only supported with ABI >= 7.9
    /// `lock_owner`: only supported with ABI >= 7.9
    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: WriteFlags,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        warn!(
            "[Not Implemented] write(ino: {ino:#x?}, fh: {fh}, offset: {offset}, \
            data.len(): {}, write_flags: {write_flags:#x?}, flags: {flags:#x?}, \
            lock_owner: {lock_owner:?})",
            data.len()
        );
        reply.error(Errno::ENOSYS);
    }

    /// Flush method.
    /// This is called on each `close()` of the opened file. Since file descriptors can
    /// be duplicated (dup, dup2, fork), for one open call there may be many flush
    /// calls. Filesystems shouldn't assume that flush will always be called after some
    /// writes, or that if will be called at all. fh will contain the value set by the
    /// open method, or will be undefined if the open method didn't set any value.
    /// NOTE: the name of the method is misleading, since (unlike fsync) the filesystem
    /// is not forced to flush pending writes. One reason to flush data, is if the
    /// filesystem wants to return write errors. If the filesystem supports file locking
    /// operations (`setlk`, `getlk`) it should remove all locks belonging to `lock_owner`.
    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        warn!("[Not Implemented] flush(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner:?})");
        reply.error(Errno::ENOSYS);
    }

    /// Release an open file.
    /// Release is called when there are no more references to an open file: all file
    /// descriptors are closed and all memory mappings are unmapped. For every open
    /// call there will be exactly one release call. The filesystem may reply with an
    /// error, but error values are not returned to `close()` or `munmap()` which triggered
    /// the release. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value. flags will contain the same flags as for
    /// open.
    ///
    /// `lock_owner` is set when the kernel asks for the open file's
    /// [`flock()`](Self::flock) locks to be released with it, which it does once
    /// [`InitFlags::FUSE_FLOCK_LOCKS`] has been negotiated. A filesystem implementing
    /// `flock()` should then release every lock held by `lock_owner`.
    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    /// Synchronize file contents.
    /// If the datasync parameter is non-zero, then only the user data should be flushed,
    /// not the meta data.
    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        warn!("[Not Implemented] fsync(ino: {ino:#x?}, fh: {fh}, datasync: {datasync})");
        reply.error(Errno::ENOSYS);
    }

    /// Open a directory.
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in fh, and
    /// use this in other all other directory stream operations (readdir, releasedir,
    /// fsyncdir). Filesystem may also implement stateless directory I/O and not store
    /// anything in fh, though that makes it impossible to implement standard conforming
    /// directory stream operations in case the contents of the directory can change
    /// between opendir and releasedir.
    ///
    /// Replying `ENOSYS` makes the kernel stop sending opendir, as with
    /// [`open()`](Self::open), so cached directory listings can then be read by any user.
    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    /// Read directory.
    /// Send a buffer filled using `buffer.fill()`, with size not exceeding the
    /// requested size. Send an empty buffer on end of stream. fh will contain the
    /// value set by the opendir method, or will be undefined if the opendir method
    /// didn't set any value.
    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        warn!("[Not Implemented] readdir(ino: {ino:#x?}, fh: {fh}, offset: {offset})");
        reply.error(Errno::ENOSYS);
    }

    /// Read directory.
    /// Send a buffer filled using `buffer.fill()`, with size not exceeding the
    /// requested size. Send an empty buffer on end of stream. fh will contain the
    /// value set by the opendir method, or will be undefined if the opendir method
    /// didn't set any value.
    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        warn!("[Not Implemented] readdirplus(ino: {ino:#x?}, fh: {fh}, offset: {offset})");
        reply.error(Errno::ENOSYS);
    }

    /// Release an open directory.
    /// For every opendir call there will be exactly one releasedir call. fh will
    /// contain the value set by the opendir method, or will be undefined if the
    /// opendir method didn't set any value.
    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    /// Synchronize directory contents.
    /// If the datasync parameter is set, then only the directory contents should
    /// be flushed, not the meta data. fh will contain the value set by the opendir
    /// method, or will be undefined if the opendir method didn't set any value.
    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        warn!("[Not Implemented] fsyncdir(ino: {ino:#x?}, fh: {fh}, datasync: {datasync})");
        reply.error(Errno::ENOSYS);
    }

    /// Get file system statistics.
    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    /// Set an extended attribute.
    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        _value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        warn!(
            "[Not Implemented] setxattr(ino: {ino:#x?}, name: {name:?}, \
            flags: {flags:#x?}, position: {position})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Get an extended attribute.
    /// If `size` is 0, the size of the value should be sent with `reply.size()`.
    /// If `size` is not 0, and the value fits, send it with `reply.data()`, or
    /// `reply.error(ERANGE)` if it doesn't.
    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        warn!("[Not Implemented] getxattr(ino: {ino:#x?}, name: {name:?}, size: {size})");
        reply.error(Errno::ENOSYS);
    }

    /// List extended attribute names.
    /// If `size` is 0, the size of the value should be sent with `reply.size()`.
    /// If `size` is not 0, and the value fits, send it with `reply.data()`, or
    /// `reply.error(ERANGE)` if it doesn't.
    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        warn!("[Not Implemented] listxattr(ino: {ino:#x?}, size: {size})");
        reply.error(Errno::ENOSYS);
    }

    /// Remove an extended attribute.
    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        warn!("[Not Implemented] removexattr(ino: {ino:#x?}, name: {name:?})");
        reply.error(Errno::ENOSYS);
    }

    /// Check file access permissions.
    /// This will be called for the `access()` system call. If the `default_permissions`
    /// mount option is given, this method is not called. This method is not called
    /// under Linux kernel versions 2.4.x
    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        warn!("[Not Implemented] access(ino: {ino:#x?}, mask: {mask})");
        reply.error(Errno::ENOSYS);
    }

    /// Create and open a file.
    /// If the file does not exist, first create it with the specified mode, and then
    /// open it. You can use any open flags in the flags parameter except `O_NOCTTY`.
    /// The filesystem can store any type of file handle (such as a pointer or index)
    /// in fh, which can then be used across all subsequent file operations including
    /// read, write, flush, release, and fsync. Additionally, the filesystem may set
    /// certain flags like `direct_io` and `keep_cache` to change the way the file is
    /// opened. See `fuse_file_info` structure in <`fuse_common.h`> for more details. If
    /// this method is not implemented or under Linux kernel versions earlier than
    /// 2.6.15, the `mknod()` and `open()` methods will be called instead.
    ///
    /// `kill_suid_gid` asks the filesystem to clear the suid and sgid bits of an existing file,
    /// because the open truncates it and the caller lacks `CAP_FSETID`. It is only ever set once
    /// `InitFlags::FUSE_HANDLE_KILLPRIV_V2` has been negotiated, since the kernel otherwise
    /// clears them itself.
    ///
    /// Honoring it is necessary but not sufficient: that capability also makes clearing the
    /// `security.capability` xattr on every write, chown and truncate the filesystem's job,
    /// and no argument reports that. See `InitFlags::FUSE_HANDLE_KILLPRIV_V2`.
    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        warn!(
            "[Not Implemented] create(parent: {parent:#x?}, name: {name:?}, mode: {mode}, \
            umask: {umask:#x?}, flags: {flags:#x?}, kill_suid_gid: {kill_suid_gid})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Test for a POSIX file lock.
    fn getlk(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: ReplyLock,
    ) {
        warn!(
            "[Not Implemented] getlk(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner}, \
            start: {start}, end: {end}, typ: {typ}, pid: {pid})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Acquire, modify or release a POSIX file lock.
    /// For POSIX threads (NPTL) there's a 1-1 relation between pid and owner, but
    /// otherwise this is not always the case.  For checking lock ownership,
    /// 'fi->owner' must be used. The `l_pid` field in 'struct flock' should only be
    /// used to fill in this field in `getlk()`. Note: if the locking methods are not
    /// implemented, the kernel will still allow file locking to work locally.
    /// Hence these are only interesting for network filesystems and similar.
    ///
    /// BSD `flock(2)` locks go to [`flock()`](Self::flock) instead, whose default implementation
    /// forwards them here.
    fn setlk(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        warn!(
            "[Not Implemented] setlk(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner}, \
            start: {start}, end: {end}, typ: {typ}, pid: {pid}, sleep: {sleep})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Acquire, convert or release a BSD file lock, as `flock(2)` takes.
    ///
    /// The kernel sends these only once [`InitFlags::FUSE_FLOCK_LOCKS`] has been negotiated, and
    /// otherwise handles `flock()` itself, locally. As with [`setlk()`](Self::setlk), this is only
    /// worth implementing where locks must be seen beyond this machine, as on a network
    /// filesystem.
    ///
    /// A `flock()` lock differs from a POSIX one. It always covers the whole file. It belongs to
    /// the open file description that `lock_owner` identifies, so it is shared by duplicated and
    /// inherited descriptors, and is not released when some other descriptor for the file is
    /// closed. It is released by an `F_UNLCK` here, or when the last descriptor of that open
    /// file is closed, which arrives as [`release()`](Self::release) with the same `lock_owner`.
    /// On Linux the two kinds of lock do not conflict with each other.
    ///
    /// `typ` is `F_RDLCK` for a shared lock, `F_WRLCK` for an exclusive one, or `F_UNLCK`. A
    /// lock already held by `lock_owner` is converted to the new type. With `sleep`, wait until
    /// the lock can be taken; without it (`LOCK_NB`), reply `EWOULDBLOCK` if it cannot be taken
    /// at once. `pid` is that of the calling process, and 0 for `F_UNLCK`.
    ///
    /// The default implementation forwards to [`setlk()`](Self::setlk) as a lock over the
    /// whole file, which is how these requests reached a filesystem before this method existed.
    fn flock(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        self.setlk(
            req,
            ino,
            fh,
            lock_owner,
            0,
            i64::MAX as u64,
            typ,
            pid,
            sleep,
            reply,
        );
    }

    /// Map block index within file to block index within device.
    /// Note: This makes sense only for block device backed filesystems mounted
    /// with the 'blkdev' option
    fn bmap(&self, _req: &Request, ino: INodeNo, blocksize: u32, idx: u64, reply: ReplyBmap) {
        warn!("[Not Implemented] bmap(ino: {ino:#x?}, blocksize: {blocksize}, idx: {idx})",);
        reply.error(Errno::ENOSYS);
    }

    /// control device
    fn ioctl(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: IoctlFlags,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        warn!(
            "[Not Implemented] ioctl(ino: {ino:#x?}, fh: {fh}, flags: {flags}, \
            cmd: {cmd}, in_data.len(): {}, out_size: {out_size})",
            in_data.len()
        );
        reply.error(Errno::ENOSYS);
    }

    /// Poll for events
    fn poll(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        ph: PollNotifier,
        events: PollEvents,
        flags: PollFlags,
        reply: ReplyPoll,
    ) {
        warn!(
            "[Not Implemented] poll(ino: {ino:#x?}, fh: {fh}, \
            ph: {ph:?}, events: {events}, flags: {flags})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Preallocate or deallocate space to a file
    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        warn!(
            "[Not Implemented] fallocate(ino: {ino:#x?}, fh: {fh}, \
            offset: {offset}, length: {length}, mode: {mode})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Reposition read/write file offset
    fn lseek(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        warn!(
            "[Not Implemented] lseek(ino: {ino:#x?}, fh: {fh}, \
            offset: {offset}, whence: {whence})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Copy the specified range from the source inode to the destination inode
    fn copy_file_range(
        &self,
        _req: &Request,
        ino_in: INodeNo,
        fh_in: FileHandle,
        offset_in: u64,
        ino_out: INodeNo,
        fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        warn!(
            "[Not Implemented] copy_file_range(ino_in: {ino_in:#x?}, fh_in: {fh_in}, \
            offset_in: {offset_in}, ino_out: {ino_out:#x?}, fh_out: {fh_out}, \
            offset_out: {offset_out}, len: {len}, flags: {flags:?})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Create an anonymous file, for `open()` with `O_TMPFILE`.
    ///
    /// The file has no name and belongs to no directory. `parent` is the directory it was
    /// created in, which is where it will live if it is later given a name with `linkat()`;
    /// until then nothing can reach it by path. Reply as for [`Filesystem::create`], with
    /// an inode and an open file handle.
    ///
    /// Answering `ENOSYS`, which is the default, is permanent: the kernel stops offering
    /// `O_TMPFILE` on this connection and reports `EOPNOTSUPP` to the caller without
    /// asking again.
    fn tmpfile(
        &self,
        _req: &Request,
        parent: INodeNo,
        mode: u32,
        umask: u32,
        flags: i32,
        kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        warn!(
            "[Not Implemented] tmpfile(parent: {parent:#x?}, mode: {mode}, umask: {umask:#x?}, \
            flags: {flags:#x?}, kill_suid_gid: {kill_suid_gid})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// Synchronize the whole filesystem, for the `syncfs(2)` system call.
    ///
    /// `ino` is the root inode. Replying before everything the filesystem holds is durable
    /// defeats the point of the call, so a filesystem that cannot make that guarantee is
    /// better off leaving this unimplemented, which reports `ENOSYS` and makes the kernel
    /// stop asking for the lifetime of the connection.
    ///
    /// Note that the kernel only propagates `syncfs(2)` on `fuseblk` and virtiofs
    /// connections. A filesystem mounted by fuser is neither, so this is reachable only
    /// for a session built with [`Session::from_fd`] on such a connection. Everywhere
    /// else `syncfs(2)` succeeds without asking the filesystem anything.
    fn syncfs(&self, _req: &Request, ino: INodeNo, reply: ReplyEmpty) {
        warn!("[Not Implemented] syncfs(ino: {ino:#x?})");
        reply.error(Errno::ENOSYS);
    }

    /// macOS only: Rename the volume. Set `fuse_init_out.flags` during init to
    /// `FUSE_VOL_RENAME` to enable
    #[cfg(target_os = "macos")]
    fn setvolname(&self, _req: &Request, name: &OsStr, reply: ReplyEmpty) {
        warn!("[Not Implemented] setvolname(name: {name:?})");
        reply.error(Errno::ENOSYS);
    }

    /// macOS only (undocumented)
    #[cfg(target_os = "macos")]
    fn exchange(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        options: u64,
        reply: ReplyEmpty,
    ) {
        warn!(
            "[Not Implemented] exchange(parent: {parent:#x?}, name: {name:?}, \
            newparent: {newparent:#x?}, newname: {newname:?}, options: {options})"
        );
        reply.error(Errno::ENOSYS);
    }

    /// macOS only: Query extended times (`bkuptime` and `crtime`). Set `fuse_init_out.flags`
    /// during init to `FUSE_XTIMES` to enable
    #[cfg(target_os = "macos")]
    fn getxtimes(&self, _req: &Request, ino: INodeNo, reply: ReplyXTimes) {
        warn!("[Not Implemented] getxtimes(ino: {ino:#x?})");
        reply.error(Errno::ENOSYS);
    }
}

/// Mount the given filesystem to the given mountpoint. This function will
/// not return until the filesystem is unmounted.
///
/// NOTE: This will eventually replace `mount()`, once the API is stable
/// # Errors
/// Returns an error if the options are incorrect, or if the fuse device can't be mounted,
/// and any final error when the session comes to an end.
pub fn mount<FS: Filesystem, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &Config,
) -> io::Result<()> {
    Session::new(filesystem, mountpoint.as_ref(), options).and_then(session::Session::run)
}

/// Mount the given filesystem to the given mountpoint. This function spawns
/// a background thread to handle filesystem operations while being mounted
/// and therefore returns immediately. The returned handle should be stored
/// to reference the mounted filesystem. If it's dropped, the filesystem will
/// be unmounted.
///
/// NOTE: This is the corresponding function to mount2.
/// # Errors
/// Returns an error if the options are incorrect, or if the fuse device can't be mounted.
pub fn spawn_mount<'a, FS: Filesystem + Send + 'static + 'a, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &Config,
) -> io::Result<BackgroundSession> {
    Session::new(filesystem, mountpoint.as_ref(), options).and_then(session::Session::spawn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "macos"))]
    fn request_timeout_config(capabilities: InitFlags) -> KernelConfig {
        KernelConfig::new(
            capabilities,
            65536,
            Version(7, 44),
            false,
            SessionACL::Owner,
        )
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn set_request_timeout() {
        let mut config = request_timeout_config(InitFlags::empty());
        // A kernel without the capability can only be asked for no timeout
        assert_eq!(
            config.set_request_timeout(Duration::from_secs(5)),
            Err(Duration::ZERO)
        );
        assert_eq!(
            config.set_request_timeout(Duration::ZERO),
            Ok(Duration::ZERO)
        );

        let mut config = request_timeout_config(InitFlags::FUSE_REQUEST_TIMEOUT);
        assert!(!config.requested.contains(InitFlags::FUSE_REQUEST_TIMEOUT));
        assert_eq!(
            config.set_request_timeout(Duration::from_millis(1500)),
            Err(Duration::from_secs(2))
        );
        assert_eq!(
            config.set_request_timeout(Duration::from_secs(70_000)),
            Err(Duration::from_secs(u16::MAX.into()))
        );
        assert_eq!(
            config.set_request_timeout(Duration::from_secs(5)),
            Ok(Duration::ZERO)
        );
        assert!(config.requested.contains(InitFlags::FUSE_REQUEST_TIMEOUT));
        assert_eq!(
            config.set_request_timeout(Duration::ZERO),
            Ok(Duration::from_secs(5))
        );
        assert!(!config.requested.contains(InitFlags::FUSE_REQUEST_TIMEOUT));
    }

    /// The INIT reply carries the timeout, and the capability that tells the kernel to read it.
    /// Not on macOS, where fuser speaks protocol 7.19, whose `fuse_init_out` has neither
    /// `flags2` nor `request_timeout`
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn init_reply_carries_request_timeout() {
        use crate::ll::reply::Response;

        #[repr(C, align(8))]
        struct Aligned([u8; 104]);
        let mut request = Aligned([0; 104]);
        request.0[0..4].copy_from_slice(&104u32.to_ne_bytes());
        request.0[4..8].copy_from_slice(&26u32.to_ne_bytes()); // FUSE_INIT
        request.0[40..44].copy_from_slice(&7u32.to_ne_bytes()); // major
        request.0[44..48].copy_from_slice(&44u32.to_ne_bytes()); // minor
        let offered = InitFlags::FUSE_INIT_EXT | InitFlags::FUSE_REQUEST_TIMEOUT;
        request.0[52..56].copy_from_slice(&offered.pair().0.to_ne_bytes());
        request.0[56..60].copy_from_slice(&offered.pair().1.to_ne_bytes());
        let request = ll::AnyRequest::try_from(&request.0[..]).unwrap();
        let ll::Operation::Init(init) = request.operation().unwrap() else {
            panic!("not an INIT request");
        };

        let mut config = request_timeout_config(init.capabilities());
        config.set_request_timeout(Duration::from_secs(30)).unwrap();
        let reply = init.reply(&config).with_iovec(ll::RequestId(0), |iov| {
            iov.iter()
                .flat_map(|x| x.iter().copied())
                .collect::<Vec<u8>>()
        });
        // The 16-byte fuse_out_header comes first; flags2 is at 32 and request_timeout at 40
        // of fuse_init_out
        let flags2 = u32::from_ne_bytes(reply[16 + 32..16 + 36].try_into().unwrap());
        let timeout = u16::from_ne_bytes(reply[16 + 40..16 + 42].try_into().unwrap());
        assert_ne!(flags2 & InitFlags::FUSE_REQUEST_TIMEOUT.pair().1, 0);
        assert_eq!(timeout, 30);
    }

    /// An `i32` on Linux, but a `c_short` on macOS and the BSDs
    #[allow(clippy::unnecessary_cast)]
    const F_WRLCK: i32 = libc::F_WRLCK as i32;

    /// What reached the filesystem: which method, the lock range, type, pid and sleep
    type LockCall = (&'static str, u64, u64, i32, u32, bool);

    /// Dispatches a SETLKW for the whole file, as `flock(2)` or a POSIX lock, to `fs`
    fn dispatch_setlk<FS: Filesystem>(fs: FS, flock: bool) -> FS {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;

        #[repr(C, align(8))]
        struct Aligned([u8; 88]);
        let mut request = Aligned([0; 88]);
        request.0[0..4].copy_from_slice(&88u32.to_ne_bytes());
        request.0[4..8].copy_from_slice(&33u32.to_ne_bytes()); // FUSE_SETLKW
        request.0[8..16].copy_from_slice(&2u64.to_ne_bytes()); // unique
        request.0[16..24].copy_from_slice(&2u64.to_ne_bytes()); // nodeid
        request.0[48..56].copy_from_slice(&9u64.to_ne_bytes()); // owner
        request.0[64..72].copy_from_slice(&(i64::MAX as u64).to_ne_bytes()); // end
        request.0[72..76].copy_from_slice(&F_WRLCK.to_ne_bytes()); // typ
        request.0[76..80].copy_from_slice(&1234u32.to_ne_bytes()); // pid
        if flock {
            request.0[80..84].copy_from_slice(&ll::fuse_abi::consts::FUSE_LK_FLOCK.to_ne_bytes());
        }

        let (_kernel, device) = UnixStream::pair().unwrap();
        let fs = Arc::new(session::FilesystemHolder::new(fs));
        let se = session::SessionEventLoop {
            thread_name: "test".to_string(),
            ch: channel::Channel::new(Arc::new(dev_fuse::DevFuse::new(std::fs::File::from(
                OwnedFd::from(device),
            )))),
            filesystem: fs.clone(),
            allowed: SessionACL::All,
            session_owner: nix::unistd::Uid::from_raw(0),
            negotiated: InitFlags::FUSE_FLOCK_LOCKS,
            kernel_capabilities: InitFlags::FUSE_FLOCK_LOCKS,
            kernel_abi: None,
        };
        request::RequestWithSender::new(se.ch.sender(), &request.0, se.negotiated)
            .unwrap()
            .dispatch(&se);
        drop(se);
        Arc::try_unwrap(fs).ok().unwrap().fs.take().unwrap()
    }

    #[derive(Default)]
    struct LockRecorder(std::sync::Mutex<Vec<LockCall>>);

    impl Filesystem for LockRecorder {
        fn setlk(
            &self,
            _: &Request,
            _: INodeNo,
            _: FileHandle,
            _: LockOwner,
            start: u64,
            end: u64,
            typ: i32,
            pid: u32,
            sleep: bool,
            reply: ReplyEmpty,
        ) {
            self.0
                .lock()
                .unwrap()
                .push(("setlk", start, end, typ, pid, sleep));
            reply.ok();
        }
    }

    /// Records flock() as well, so that it no longer reaches setlk() through the default
    #[derive(Default)]
    struct FlockRecorder(LockRecorder);

    impl Filesystem for FlockRecorder {
        fn setlk(
            &self,
            req: &Request,
            ino: INodeNo,
            fh: FileHandle,
            owner: LockOwner,
            start: u64,
            end: u64,
            typ: i32,
            pid: u32,
            sleep: bool,
            reply: ReplyEmpty,
        ) {
            self.0
                .setlk(req, ino, fh, owner, start, end, typ, pid, sleep, reply);
        }
        fn flock(
            &self,
            _: &Request,
            _: INodeNo,
            _: FileHandle,
            _: LockOwner,
            typ: i32,
            pid: u32,
            sleep: bool,
            reply: ReplyEmpty,
        ) {
            self.0
                .0
                .lock()
                .unwrap()
                .push(("flock", 0, 0, typ, pid, sleep));
            reply.ok();
        }
    }

    #[test]
    fn flock_requests_go_to_flock_and_posix_ones_to_setlk() {
        let posix = dispatch_setlk(FlockRecorder::default(), false);
        assert_eq!(
            *posix.0.0.lock().unwrap(),
            [("setlk", 0, i64::MAX as u64, F_WRLCK, 1234, true)]
        );
        let flock = dispatch_setlk(FlockRecorder::default(), true);
        assert_eq!(
            *flock.0.0.lock().unwrap(),
            [("flock", 0, 0, F_WRLCK, 1234, true)]
        );
    }

    /// A filesystem that does not implement flock() gets the request in setlk(), as it did
    /// before flock() existed
    #[test]
    fn default_flock_forwards_to_setlk_over_the_whole_file() {
        let fs = dispatch_setlk(LockRecorder::default(), true);
        assert_eq!(
            *fs.0.lock().unwrap(),
            [("setlk", 0, i64::MAX as u64, F_WRLCK, 1234, true)]
        );
    }

    #[test]
    fn file_attr_from_metadata() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"0123456789").unwrap();
        // Ask for every mode bit the protocol carries, so that a conversion masking the wrong
        // width shows up here. FreeBSD refuses setgid on a file whose group the caller is not
        // in, where Linux drops the bit silently, so take whatever the platform stored rather
        // than assuming the request succeeded
        let set = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o6754)).is_ok();

        let metadata = std::fs::metadata(&file).unwrap();
        let attr = FileAttr::try_from(&metadata).unwrap();

        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.size, 10);
        // The file type bits belong to `kind`, and must not leak into `perm`
        assert_eq!(u32::from(attr.perm), metadata.mode() & 0o7777);
        // ...which only tests anything if the raw mode has bits outside that mask to drop
        assert_ne!(metadata.mode() & !0o7777, 0);
        if set {
            // Where the platform took the whole request, every bit above the permissions has
            // to survive too, which is what a conversion masking the wrong width would lose
            assert_eq!(attr.perm, 0o6754);
        }
        assert_eq!(attr.ino, INodeNo(metadata.ino()));
        assert_eq!(attr.uid, metadata.uid());
        assert_eq!(attr.gid, metadata.gid());
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.blocks, metadata.blocks());
        assert_eq!(
            attr.mtime,
            time::system_time_from_time(metadata.mtime(), metadata.mtime_nsec() as u32,)
        );
        // std exposes no accessor for the BSD flags, so they are always absent
        assert_eq!(attr.flags, 0);

        // Nothing but a device file has an rdev, whatever the platform left in the field
        assert_eq!(attr.rdev, 0);

        let attr = FileAttr::try_from(&std::fs::metadata(dir.path()).unwrap()).unwrap();
        assert_eq!(attr.kind, FileType::Directory);

        // A symlink only reports as one when the metadata was taken without following it
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let attr = FileAttr::try_from(&std::fs::symlink_metadata(&link).unwrap()).unwrap();
        assert_eq!(attr.kind, FileType::Symlink);
        // FreeBSD's UFS keeps a fast symlink's target in the inode field that a device file
        // uses for its rdev, so reading it here would report the target's first eight bytes
        assert_eq!(attr.rdev, 0);
        let attr = FileAttr::try_from(&std::fs::metadata(&link).unwrap()).unwrap();
        assert_eq!(attr.kind, FileType::RegularFile);
    }

    #[test]
    fn file_attr_from_metadata_of_a_device() {
        use std::os::unix::fs::MetadataExt;

        // Every platform this builds on has /dev/null, and it is a character device on all of
        // them, but its device number is assigned by the system and is not worth predicting
        let metadata = std::fs::metadata("/dev/null").unwrap();
        let attr = FileAttr::try_from(&metadata).unwrap();

        assert_eq!(attr.kind, FileType::CharDevice);
        assert_eq!(u64::from(attr.rdev), metadata.rdev());
        assert_ne!(attr.rdev, 0);
    }

    #[test]
    fn file_attr_from_metadata_of_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("p");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();

        let attr = FileAttr::try_from(&std::fs::symlink_metadata(&fifo).unwrap()).unwrap();
        assert_eq!(attr.kind, FileType::NamedPipe);
        assert_eq!(attr.perm, 0o400);
    }

    #[test]
    fn kernel_config_set_max_write_bounds() {
        let mut config = KernelConfig::new(
            InitFlags::empty(),
            65536,
            Version(7, 31),
            true,
            SessionACL::All,
        );
        // Values the kernel would not honor (it clamps max_write below 4096 up
        // to 4096) are rejected with the nearest value that will take effect
        assert_eq!(config.set_max_write(0), Err(MIN_WRITE_SIZE as u32));
        assert_eq!(
            config.set_max_write(MIN_WRITE_SIZE as u32 - 1),
            Err(MIN_WRITE_SIZE as u32)
        );
        // Values beyond the session's read buffer are rejected likewise
        assert_eq!(
            config.set_max_write(MAX_WRITE_SIZE as u32 + 1),
            Err(MAX_WRITE_SIZE as u32)
        );
        // Rejected calls must leave the configured value unchanged
        assert_eq!(config.max_write, MAX_WRITE_SIZE as u32);
        // Both bounds themselves are accepted, returning the previous value
        assert_eq!(
            config.set_max_write(MIN_WRITE_SIZE as u32),
            Ok(MAX_WRITE_SIZE as u32)
        );
        assert_eq!(
            config.set_max_write(MAX_WRITE_SIZE as u32),
            Ok(MIN_WRITE_SIZE as u32)
        );
    }

    /// FUSE_ALLOW_IDMAP is refused unless the mount can carry it, since the kernel refuses
    /// the connection without default_permissions and fuser cannot enforce an owner-only ACL
    /// once the caller's ids are withheld
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn add_capabilities_idmap_needs_default_permissions_and_allow_other() {
        let cases = [
            (true, SessionACL::All, true),
            (false, SessionACL::All, false),
            (true, SessionACL::Owner, false),
            (true, SessionACL::RootAndOwner, false),
            (false, SessionACL::Owner, false),
        ];
        for (default_permissions, acl, accepted) in cases {
            let mut config = KernelConfig::new(
                InitFlags::all(),
                65536,
                Version(7, 43),
                default_permissions,
                acl,
            );
            let result = config.add_capabilities(InitFlags::FUSE_ALLOW_IDMAP);
            assert_eq!(
                result.is_ok(),
                accepted,
                "default_permissions={default_permissions} acl={acl:?} should                  {} the capability",
                if accepted { "accept" } else { "refuse" }
            );
            if !accepted {
                assert_eq!(result, Err(InitFlags::FUSE_ALLOW_IDMAP));
                assert!(!config.requested.contains(InitFlags::FUSE_ALLOW_IDMAP));
            } else {
                assert!(config.requested.contains(InitFlags::FUSE_ALLOW_IDMAP));
            }
        }
    }

    /// Negotiating POSIX ACLs puts default_permissions in force just as the mount option does,
    /// the kernel setting it from that flag before it validates this one, so it satisfies the
    /// requirement on its own - but only where the kernel offers it, since a capability it
    /// does not offer is dropped from the negotiated set and sets nothing
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn add_capabilities_idmap_accepts_posix_acl_for_default_permissions() {
        // Both in one call
        let mut config = KernelConfig::new(
            InitFlags::all(),
            65536,
            Version(7, 43),
            false,
            SessionACL::All,
        );
        assert_eq!(
            config.add_capabilities(InitFlags::FUSE_POSIX_ACL | InitFlags::FUSE_ALLOW_IDMAP),
            Ok(())
        );

        // ACLs asked for first, in an earlier call
        let mut config = KernelConfig::new(
            InitFlags::all(),
            65536,
            Version(7, 43),
            false,
            SessionACL::All,
        );
        assert_eq!(config.add_capabilities(InitFlags::FUSE_POSIX_ACL), Ok(()));
        assert_eq!(config.add_capabilities(InitFlags::FUSE_ALLOW_IDMAP), Ok(()));

        // A kernel without POSIX ACLs would drop them, leaving nothing to force
        // default_permissions and a connection the kernel would refuse
        let mut config = KernelConfig::new(
            InitFlags::all() & !InitFlags::FUSE_POSIX_ACL,
            65536,
            Version(7, 43),
            false,
            SessionACL::All,
        );
        assert_eq!(
            config.add_capabilities(InitFlags::FUSE_POSIX_ACL | InitFlags::FUSE_ALLOW_IDMAP),
            Err(InitFlags::FUSE_POSIX_ACL | InitFlags::FUSE_ALLOW_IDMAP)
        );

        // Neither one on its own is enough without allow_other
        let mut config = KernelConfig::new(
            InitFlags::all(),
            65536,
            Version(7, 43),
            false,
            SessionACL::Owner,
        );
        assert_eq!(
            config.add_capabilities(InitFlags::FUSE_POSIX_ACL | InitFlags::FUSE_ALLOW_IDMAP),
            Err(InitFlags::FUSE_ALLOW_IDMAP)
        );
    }

    /// A kernel that does not offer it cannot have it forced on, whatever the mount looks like
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn add_capabilities_idmap_needs_the_kernel_to_offer_it() {
        let mut config = KernelConfig::new(
            InitFlags::all() & !InitFlags::FUSE_ALLOW_IDMAP,
            65536,
            Version(7, 43),
            true,
            SessionACL::All,
        );
        assert_eq!(
            config.add_capabilities(InitFlags::FUSE_ALLOW_IDMAP),
            Err(InitFlags::FUSE_ALLOW_IDMAP)
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn add_capabilities_refuses_unimplemented() {
        // A kernel advertising everything, so only fuser's own limits can refuse anything
        let mut config = KernelConfig::new(
            InitFlags::all(),
            65536,
            Version(7, 43),
            true,
            SessionACL::All,
        );
        let before = config.requested;
        for capability in UNSUPPORTED_CAPABILITIES {
            assert_eq!(config.add_capabilities(capability), Err(capability));
        }
        // Now that setattr, open and create carry kill_suid_gid, this one is honored rather
        // than refused, and must not drift back into the refused set
        assert_eq!(
            config.add_capabilities(InitFlags::FUSE_HANDLE_KILLPRIV_V2),
            Ok(())
        );
        // A capability fuser implements is still accepted from the same kernel
        assert_eq!(config.add_capabilities(InitFlags::FUSE_POSIX_ACL), Ok(()));
        assert_eq!(
            config.requested,
            before | InitFlags::FUSE_HANDLE_KILLPRIV_V2 | InitFlags::FUSE_POSIX_ACL
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn refused_capabilities_are_never_requested_by_default() {
        // Below bit 32 a capability aliases a macFUSE one, some of which fuser requests itself.
        // Refusing a bit fuser goes on to request would be incoherent, and on macOS would break
        // the operations built on it, so the two sets must stay disjoint on every platform
        assert!(UNSUPPORTED_CAPABILITIES.intersection(INIT_FLAGS).is_empty());
    }

    /// A macOS filesystem is case-sensitive unless it asks otherwise (#749)
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_defaults_are_case_sensitive() {
        assert!(!default_init_flags(InitFlags::all()).contains(InitFlags::FUSE_CASE_INSENSITIVE));
    }

    /// Bit 22 is Linux's FUSE_MAX_PAGES but macFUSE's FUSE_PAYLOAD_BUF, which fuser does not
    /// implement, so it is not requested on macOS however the kernel offers it (#751)
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_defaults_do_not_request_linux_only_bits() {
        let bit_22 = InitFlags::from_bits_retain(1 << 22);
        assert!(!default_init_flags(bit_22).contains(bit_22));
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn add_capabilities_refuses_all_or_nothing() {
        // Advertise everything except one capability fuser does implement
        let capabilities = InitFlags::all() - InitFlags::FUSE_POSIX_ACL;
        let mut config =
            KernelConfig::new(capabilities, 65536, Version(7, 43), true, SessionACL::All);
        let before = config.requested;
        // Both reasons for refusing are reported together, and a capability that would have
        // been accepted on its own is not added
        assert_eq!(
            config.add_capabilities(
                InitFlags::FUSE_POSIX_ACL
                    | InitFlags::FUSE_SECURITY_CTX
                    | InitFlags::FUSE_ASYNC_DIO
            ),
            Err(InitFlags::FUSE_POSIX_ACL | InitFlags::FUSE_SECURITY_CTX)
        );
        assert_eq!(config.requested, before);
    }
}
