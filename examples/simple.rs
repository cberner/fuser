#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform

use std::cmp::min;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use clap::Parser;
use fuser::AccessFlags;
use fuser::BsdFileFlags;
use fuser::Config;
use fuser::Errno;
use fuser::FileHandle;
use fuser::Filesystem;
use fuser::FopenFlags;
use fuser::INodeNo;
use fuser::InitFlags;
use fuser::KernelConfig;
use fuser::LockOwner;
use fuser::MountOption;
use fuser::OpenAccMode;
use fuser::OpenFlags;
use fuser::Owner;
use fuser::RenameFlags;
use fuser::ReplyAttr;
use fuser::ReplyCreate;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEmpty;
use fuser::ReplyEntry;
use fuser::ReplyOpen;
use fuser::ReplyStatfs;
use fuser::ReplyWrite;
use fuser::ReplyXattr;
use fuser::Request;
use fuser::SessionACL;
use fuser::TimeOrNow;
use fuser::TimeOrNow::Now;
use fuser::WriteFlags;
use log::LevelFilter;
use log::debug;
use log::error;
use log::info;
use log::warn;
use serde::Deserialize;
use serde::Serialize;

#[derive(Parser)]
#[command(version, author = "Christopher Berner")]
struct Args {
    /// Set local directory used to store data
    #[clap(long, default_value = "/tmp/fuser")]
    data_dir: String,

    // TODO: make positional like other examples.
    /// Act as a client, and mount FUSE at given path
    #[clap(long, default_value = "")]
    mount_point: String,

    /// Mount FUSE with direct IO
    #[clap(long, requires = "mount_point")]
    direct_io: bool,

    /// Automatically unmount FUSE when process exits
    #[clap(long)]
    auto_unmount: bool,

    /// Run a filesystem check
    #[clap(long)]
    fsck: bool,

    /// Enable setuid support when run as root
    #[clap(long)]
    suid: bool,

    /// Allow device files on this filesystem to be opened, when run as root. Off by default,
    /// as it is for any other filesystem: a device node the mount's own users can create is a
    /// way to reach hardware the kernel would not otherwise let them touch
    #[clap(long)]
    dev: bool,

    #[clap(long, default_value_t = 1)]
    n_threads: usize,

    /// Sets the level of verbosity
    #[clap(short, action = clap::ArgAction::Count)]
    v: u8,
}

const BLOCK_SIZE: u32 = 512;

// Inode flags, as `chattr` sets them and `lsattr` reports them. Only these three change
// behavior, and only Linux has the ioctls that set them - but the fields they gate are not
// themselves Linux-only, so the constants are not gated either
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;
const FS_NOATIME_FL: u32 = 0x0000_0080;

// The rest are stored and reported so that they round-trip, which only the Linux ioctls do
#[cfg(target_os = "linux")]
const FS_SECRM_FL: u32 = 0x0000_0001;
#[cfg(target_os = "linux")]
const FS_UNRM_FL: u32 = 0x0000_0002;
#[cfg(target_os = "linux")]
const FS_SYNC_FL: u32 = 0x0000_0008;
#[cfg(target_os = "linux")]
const FS_NODUMP_FL: u32 = 0x0000_0040;
#[cfg(target_os = "linux")]
const FS_DIRSYNC_FL: u32 = 0x0001_0000;
#[cfg(target_os = "linux")]
const FS_TOPDIR_FL: u32 = 0x0002_0000;
const MAX_NAME_LENGTH: u32 = 255;
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;

// Top two file handle bits are used to store permissions
// Note: This isn't safe, since the client can modify those bits. However, this implementation
// is just a toy
const FILE_HANDLE_READ_BIT: u64 = 1 << 63;
const FILE_HANDLE_WRITE_BIT: u64 = 1 << 62;

/// The flags above are the whole set this filesystem accepts. Refusing the others is what
/// tells `chattr` that, say, compression is unavailable here
#[cfg(target_os = "linux")]
const SUPPORTED_FS_FLAGS: u32 = FS_SECRM_FL
    | FS_UNRM_FL
    | FS_SYNC_FL
    | FS_IMMUTABLE_FL
    | FS_APPEND_FL
    | FS_NODUMP_FL
    | FS_NOATIME_FL
    | FS_DIRSYNC_FL
    | FS_TOPDIR_FL;

// The same flags in the unrelated encoding that `fsxattr` uses, which is the one `xfs_io
// chattr` and `xfs_io lsattr` speak
#[cfg(target_os = "linux")]
const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
#[cfg(target_os = "linux")]
const FS_XFLAG_APPEND: u32 = 0x0000_0010;
#[cfg(target_os = "linux")]
const FS_XFLAG_SYNC: u32 = 0x0000_0020;
#[cfg(target_os = "linux")]
const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
#[cfg(target_os = "linux")]
const FS_XFLAG_NODUMP: u32 = 0x0000_0080;

/// `struct fsxattr`, of which only the leading `fsx_xflags` is meaningful here
#[cfg(target_os = "linux")]
const FSXATTR_SIZE: usize = 28;

// The kernel turns chattr(1), lsattr(1) and their xfs_io equivalents into these four ioctls
#[cfg(target_os = "linux")]
const FS_IOC_GETFLAGS: u32 = nix::request_code_read!('f', 1, size_of::<libc::c_long>()) as u32;
#[cfg(target_os = "linux")]
const FS_IOC_SETFLAGS: u32 = nix::request_code_write!('f', 2, size_of::<libc::c_long>()) as u32;
#[cfg(target_os = "linux")]
const FS_IOC_FSGETXATTR: u32 = nix::request_code_read!('X', 31, FSXATTR_SIZE) as u32;
#[cfg(target_os = "linux")]
const FS_IOC_FSSETXATTR: u32 = nix::request_code_write!('X', 32, FSXATTR_SIZE) as u32;

/// The `FS_*_FL` flags this filesystem honors, in the `fsxattr` encoding
#[cfg(target_os = "linux")]
const FLAG_TO_XFLAG: [(u32, u32); 5] = [
    (FS_IMMUTABLE_FL, FS_XFLAG_IMMUTABLE),
    (FS_APPEND_FL, FS_XFLAG_APPEND),
    (FS_SYNC_FL, FS_XFLAG_SYNC),
    (FS_NOATIME_FL, FS_XFLAG_NOATIME),
    (FS_NODUMP_FL, FS_XFLAG_NODUMP),
];

#[cfg(target_os = "linux")]
fn xflags_from_flags(flags: u32) -> u32 {
    FLAG_TO_XFLAG
        .iter()
        .filter(|(flag, _)| flags & flag != 0)
        .fold(0, |xflags, (_, xflag)| xflags | xflag)
}

/// The inverse of [`xflags_from_flags`], or `None` if a flag with no counterpart was asked for
#[cfg(target_os = "linux")]
fn flags_from_xflags(xflags: u32) -> Option<u32> {
    let known = FLAG_TO_XFLAG
        .iter()
        .fold(0, |known, (_, xflag)| known | xflag);
    (xflags & !known == 0).then(|| {
        FLAG_TO_XFLAG
            .iter()
            .filter(|(_, xflag)| xflags & xflag != 0)
            .fold(0, |flags, (flag, _)| flags | flag)
    })
}

const FMODE_EXEC: i32 = 0x20;

type DirectoryDescriptor = BTreeMap<Vec<u8>, (u64, FileKind)>;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
enum FileKind {
    File,
    Directory,
    Symlink,
    // Appended, so the ordinals of the three above survive in already-written inodes
    CharDevice,
    BlockDevice,
    NamedPipe,
    Socket,
}

impl From<FileKind> for fuser::FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => fuser::FileType::RegularFile,
            FileKind::Directory => fuser::FileType::Directory,
            FileKind::Symlink => fuser::FileType::Symlink,
            FileKind::CharDevice => fuser::FileType::CharDevice,
            FileKind::BlockDevice => fuser::FileType::BlockDevice,
            FileKind::NamedPipe => fuser::FileType::NamedPipe,
            FileKind::Socket => fuser::FileType::Socket,
        }
    }
}

#[derive(Debug)]
enum XattrNamespace {
    Security,
    System,
    Trusted,
    User,
}

fn parse_xattr_namespace(key: &[u8]) -> Result<XattrNamespace, Errno> {
    let user = b"user.";
    if key.len() < user.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..user.len()].eq(user) {
        return Ok(XattrNamespace::User);
    }

    let system = b"system.";
    if key.len() < system.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..system.len()].eq(system) {
        return Ok(XattrNamespace::System);
    }

    let trusted = b"trusted.";
    if key.len() < trusted.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..trusted.len()].eq(trusted) {
        return Ok(XattrNamespace::Trusted);
    }

    let security = b"security";
    if key.len() < security.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..security.len()].eq(security) {
        return Ok(XattrNamespace::Security);
    }

    return Err(Errno::ENOTSUP);
}

/// Strip suid, and sgid where the kernel would, from a file the caller has just modified.
///
/// Two independent rules decide sgid. The killpriv rule drops it from a group-executable file,
/// where it means setgid-on-exec rather than the old mandatory-locking mark. Separately, a
/// caller outside the file's group drops it, which is why an unprivileged write to a root-owned
/// setgid file clears the bit whatever its exec bits are. Either rule alone is enough, so a
/// `02666` file loses the bit to an outside-group caller despite having no exec bits and no
/// suid to clear alongside it.
///
/// The group tested is the one the file has now, not the one a chown in the same request is
/// about to give it: chgrp'ing a setgid file to a group the caller is in still clears the bit
/// when the caller was outside the group it is moving away from.
fn clear_suid_sgid(attr: &mut InodeAttributes, req: &Request, privilege: Privilege) {
    attr.mode &= !libc::S_ISUID as u16;

    let sgid_exec = attr.mode & (libc::S_ISGID | libc::S_IXGRP) as u16
        == (libc::S_ISGID | libc::S_IXGRP) as u16;
    let outside_group = privilege.lacks_fsetid(req)
        && caller_gid(req) != attr.gid
        && !get_groups(req.pid()).contains(&attr.gid);
    if sgid_exec || outside_group {
        attr.mode &= !libc::S_ISGID as u16;
    }
}

/// Whether the request already establishes that the caller lacks `CAP_FSETID`, which decides
/// whether the outside-group half of the sgid rule applies.
enum Privilege {
    /// The kernel worked `CAP_FSETID` into `kill_suid_gid` itself, as `write` and `truncate`
    /// do via `setattr_should_drop_suidgid()`. Being asked at all proves the caller lacks it,
    /// so the capability set does not have to be read back
    KnownLacking,
    /// The request settles nothing: `chown` asks whatever the caller holds, and `fallocate`
    /// and `copy_file_range` carry no signal at all. The caller has to be inspected
    Unknown,
}

impl Privilege {
    fn lacks_fsetid(&self, req: &Request) -> bool {
        match self {
            Privilege::KnownLacking => true,
            Privilege::Unknown => !has_fsetid(req.pid(), caller_uid(req)),
        }
    }
}

/// Both killpriv capabilities make the kernel stop removing file capabilities, so they have to
/// go on every write, chown and truncate. Unlike suid and sgid, no request flag reports this:
/// the operation is itself the signal
fn clear_file_capabilities(attr: &mut InodeAttributes) {
    attr.xattrs.remove(b"security.capability".as_slice());
}

/// Drop privileges for an operation the kernel hands over without saying whether to.
///
/// Negotiating either killpriv capability stops the kernel removing privileges itself, but
/// `FUSE_FALLOCATE` and `FUSE_COPY_FILE_RANGE` carry nothing like the `kill_suid_gid` argument
/// that write, setattr, open and create get, so the filesystem has to work out for itself
/// whether the caller holds `CAP_FSETID`, and leave suid and sgid alone if it does.
///
/// File capabilities go regardless, as they do on write, chown and truncate: `CAP_FSETID` covers
/// suid and sgid only.
///
/// Call this only when a killpriv capability was negotiated: without one the kernel still
/// removes privileges itself, and clearing here as well would strip bits it had decided to keep
fn clear_privileges_unprompted(attr: &mut InodeAttributes, req: &Request) {
    if !has_fsetid(req.pid(), caller_uid(req)) {
        // The capability set has just answered the question, so do not read it a second time
        clear_suid_sgid(attr, req, Privilege::KnownLacking);
    }
    clear_file_capabilities(attr);
}

fn creation_gid(parent: &InodeAttributes, gid: u32) -> u32 {
    if parent.mode & libc::S_ISGID as u16 != 0 {
        return parent.gid;
    }

    gid
}

fn xattr_access_check(
    key: &[u8],
    access_mask: i32,
    inode_attrs: &InodeAttributes,
    request: &Request,
) -> Result<(), Errno> {
    // Extended attributes are part of the inode, so both flags cover them: neither an
    // immutable nor an append-only inode accepts a change to one
    if access_mask != libc::R_OK {
        inode_attrs.check_removable()?;
    }

    match parse_xattr_namespace(key)? {
        XattrNamespace::Security => {
            if access_mask != libc::R_OK && caller_uid(request) != 0 {
                return Err(Errno::EPERM);
            }
        }
        XattrNamespace::Trusted => {
            if caller_uid(request) != 0 {
                return Err(Errno::EPERM);
            }
        }
        XattrNamespace::System => {
            if key.eq(b"system.posix_acl_access") {
                if !check_access(
                    inode_attrs.uid,
                    inode_attrs.gid,
                    inode_attrs.mode,
                    caller_uid(request),
                    caller_gid(request),
                    AccessFlags::from_bits_retain(access_mask),
                ) {
                    return Err(Errno::EPERM);
                }
            } else if caller_uid(request) != 0 {
                return Err(Errno::EPERM);
            }
        }
        XattrNamespace::User => {
            if !check_access(
                inode_attrs.uid,
                inode_attrs.gid,
                inode_attrs.mode,
                caller_uid(request),
                caller_gid(request),
                AccessFlags::from_bits_retain(access_mask),
            ) {
                return Err(Errno::EPERM);
            }
        }
    }

    Ok(())
}

/// The caller's uid, which this filesystem is always given. The kernel withholds ids only on
/// an idmapped mount, which needs `FUSE_ALLOW_IDMAP`, and this example does not request it
fn caller_uid(req: &Request) -> u32 {
    req.uid()
        .expect("ids are withheld only on an idmapped mount")
}

/// The caller's gid, always present for the same reason as [`caller_uid`]
fn caller_gid(req: &Request) -> u32 {
    req.gid()
        .expect("ids are withheld only on an idmapped mount")
}

fn time_now() -> (i64, u32) {
    time_from_system_time(&SystemTime::now())
}

// As in a timespec, nanoseconds count forward from the whole second even when it
// is negative: the represented time is secs + nsecs / 1e9
fn system_time_from_time(secs: i64, nsecs: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else if nsecs == 0 {
        UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0)
    } else {
        UNIX_EPOCH - Duration::new(secs.unsigned_abs() - 1, 1_000_000_000 - nsecs)
    }
}

fn time_from_system_time(system_time: &SystemTime) -> (i64, u32) {
    // Convert to signed 64-bit time with epoch at 0
    match system_time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_nanos()),
        Err(before_epoch_error) => {
            let d = before_epoch_error.duration();
            if d.subsec_nanos() == 0 {
                (-(d.as_secs() as i64), 0)
            } else {
                (-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct InodeAttributes {
    pub inode: u64,
    pub open_file_handles: u64, // Ref count of open file handles to this inode
    pub size: u64,
    pub last_accessed: (i64, u32),
    pub last_modified: (i64, u32),
    pub last_metadata_changed: (i64, u32),
    /// Time of creation, which `statx(2)` reports as `stx_btime` and nothing ever changes
    pub created: (i64, u32),
    pub kind: FileKind,
    // Permissions and special mode bits
    pub mode: u16,
    pub hardlinks: u32,
    pub uid: u32,
    pub gid: u32,
    /// Device number, which only a character or block device carries
    pub rdev: u32,
    /// Inode flags, in the `FS_*_FL` encoding that `chattr` uses
    pub flags: u32,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl InodeAttributes {
    fn is_immutable(&self) -> bool {
        self.flags & FS_IMMUTABLE_FL != 0
    }

    fn is_append_only(&self) -> bool {
        self.flags & FS_APPEND_FL != 0
    }

    fn is_noatime(&self) -> bool {
        self.flags & FS_NOATIME_FL != 0
    }

    /// Nothing writes to an immutable inode. A directory counts: adding an entry to one is a
    /// write to the directory, so a create inside it fails before permissions are consulted
    fn check_writable(&self) -> Result<(), Errno> {
        if self.is_immutable() {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// Unlinking or renaming needs this of both the entry and its parent. Append-only refuses
    /// as well, since it exists to keep what has already been written
    fn check_removable(&self) -> Result<(), Errno> {
        if self.is_immutable() || self.is_append_only() {
            return Err(Errno::EPERM);
        }
        Ok(())
    }
}

impl From<InodeAttributes> for fuser::FileAttr {
    fn from(attrs: InodeAttributes) -> Self {
        fuser::FileAttr {
            ino: INodeNo(attrs.inode),
            size: attrs.size,
            blocks: attrs.size.div_ceil(u64::from(BLOCK_SIZE)),
            atime: system_time_from_time(attrs.last_accessed.0, attrs.last_accessed.1),
            mtime: system_time_from_time(attrs.last_modified.0, attrs.last_modified.1),
            ctime: system_time_from_time(
                attrs.last_metadata_changed.0,
                attrs.last_metadata_changed.1,
            ),
            crtime: system_time_from_time(attrs.created.0, attrs.created.1),
            kind: attrs.kind.into(),
            perm: attrs.mode,
            nlink: attrs.hardlinks,
            uid: attrs.uid,
            gid: attrs.gid,
            rdev: attrs.rdev,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }
}

// Stores inode metadata data in "$data_dir/inodes" and file contents in "$data_dir/contents"
// Directory data is stored in the file's contents, as a serialized DirectoryDescriptor
struct SimpleFS {
    data_dir: String,
    next_file_handle: AtomicU64,
    direct_io: bool,
    suid_support: bool,
    /// Whether a killpriv capability was negotiated, and so whether removing privileges is
    /// this filesystem's job rather than the kernel's. Distinct from `suid_support`, which
    /// only says whether the caller asked for setuid support
    killpriv_negotiated: bool,
}

impl SimpleFS {
    fn new(data_dir: String, direct_io: bool, suid_support: bool) -> SimpleFS {
        SimpleFS {
            data_dir,
            next_file_handle: AtomicU64::new(1),
            direct_io,
            suid_support,
            killpriv_negotiated: false,
        }
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        if self.suid_support {
            mode as u16
        } else {
            (mode & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16
        }
    }

    fn allocate_next_inode(&self) -> INodeNo {
        let path = Path::new(&self.data_dir).join("superblock");
        let current_inode = match File::open(&path) {
            Ok(file) => INodeNo(rmp_serde::from_read(file).unwrap()),
            _ => INodeNo::ROOT,
        };

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        rmp_serde::encode::write(&mut file, &(current_inode.0 + 1)).unwrap();

        INodeNo(current_inode.0 + 1)
    }

    fn allocate_next_file_handle(&self, read: bool, write: bool) -> u64 {
        let mut fh = self.next_file_handle.fetch_add(1, Ordering::SeqCst);
        // Assert that we haven't run out of file handles
        assert!(fh < FILE_HANDLE_READ_BIT.min(FILE_HANDLE_WRITE_BIT));
        if read {
            fh |= FILE_HANDLE_READ_BIT;
        }
        if write {
            fh |= FILE_HANDLE_WRITE_BIT;
        }

        fh
    }

    fn check_file_handle_read(file_handle: u64) -> bool {
        (file_handle & FILE_HANDLE_READ_BIT) != 0
    }

    fn check_file_handle_write(file_handle: u64) -> bool {
        (file_handle & FILE_HANDLE_WRITE_BIT) != 0
    }

    fn content_path(&self, inode: INodeNo) -> PathBuf {
        Path::new(&self.data_dir)
            .join("contents")
            .join(inode.to_string())
    }

    /// Whether the backing directory looks able to take a preallocation of `length` bytes at
    /// `offset`.
    ///
    /// The range is rounded out to whole backing blocks before being compared, since a range
    /// that starts mid-block touches one more block than its length alone implies.
    ///
    /// This is a preflight rather than a reservation, and cannot be exact: the backing
    /// filesystem spends blocks on its own metadata, and nothing holds the space between this
    /// answer and the call it guards. It exists to refuse the requests that are impossible by
    /// orders of magnitude, not to predict the last block. An unreadable backing store is
    /// therefore allowed through rather than refused, so that a `statvfs` this filesystem
    /// cannot answer does not turn every preallocation into ENOSPC.
    ///
    /// The counts widen to `u64` explicitly because `statvfs` reports them in types whose
    /// width varies by platform: 64 bits on Linux, 32 on macOS.
    ///
    /// Gated to match its only caller, the `fallocate` that FUSE offers on Linux alone
    #[cfg(target_os = "linux")]
    fn backing_store_can_take(&self, offset: u64, length: u64) -> bool {
        let Ok(stat) = nix::sys::statvfs::statvfs(Path::new(&self.data_dir)) else {
            return true;
        };
        let block_size = (stat.fragment_size() as u64).max(1);
        let first_block = offset / block_size;
        let last_block = offset.saturating_add(length).div_ceil(block_size);
        last_block.saturating_sub(first_block) <= stat.blocks_available() as u64
    }

    /// Attributes as the kernel sees them. The block count comes from the backing file rather
    /// than from the size, so that a file with holes reports the space it actually occupies
    fn file_attr(&self, attrs: InodeAttributes) -> fuser::FileAttr {
        let fallback = attrs.size.div_ceil(u64::from(BLOCK_SIZE));
        let blocks = fs::metadata(self.content_path(INodeNo(attrs.inode)))
            .map_or(fallback, |metadata| metadata.blocks());
        fuser::FileAttr {
            blocks,
            ..attrs.into()
        }
    }

    fn get_directory_content(&self, inode: INodeNo) -> Result<DirectoryDescriptor, Errno> {
        let path = Path::new(&self.data_dir)
            .join("contents")
            .join(inode.to_string());
        match File::open(path) {
            Ok(file) => Ok(rmp_serde::from_read(file).unwrap()),
            _ => Err(Errno::ENOENT),
        }
    }

    fn write_directory_content(&self, inode: INodeNo, entries: &DirectoryDescriptor) {
        let path = Path::new(&self.data_dir)
            .join("contents")
            .join(inode.to_string());
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        rmp_serde::encode::write(&mut file, &entries).unwrap();
    }

    fn get_inode(&self, inode: INodeNo) -> Result<InodeAttributes, Errno> {
        let path = Path::new(&self.data_dir)
            .join("inodes")
            .join(inode.to_string());
        match File::open(path) {
            Ok(file) => Ok(rmp_serde::from_read(file).unwrap()),
            _ => Err(Errno::ENOENT),
        }
    }

    /// Record that an inode was read, following the kernel's default `relatime` policy.
    ///
    /// Moving atime on every read would mean a write per read, so it only moves when it is no
    /// newer than mtime or ctime - that is, when nothing has read the inode since it last
    /// changed - or when it has gone stale by more than a day. That preserves the one thing a
    /// reader can draw from atime: an atime older than mtime means nobody has looked since the
    /// last write.
    ///
    /// A mount can ask for `noatime` or `strictatime` instead, but no FUSE request reports
    /// which the mount used and this example takes no option for it, so the kernel's default
    /// is the only policy on offer.
    ///
    /// `O_NOATIME` on the caller's handle is honored by `read()`, which is given the flag, on
    /// Linux - neither macOS nor FreeBSD has the flag.
    /// `readdir()` and `copy_file_range()` are not, and would have to carry it over from the
    /// `open()` that set it, so a caller using it there still moves atime
    fn touch_atime(&self, attrs: &mut InodeAttributes) {
        // `chattr +A` asks for exactly this: leave the access time alone. Honoring it here
        // covers every caller, including the readdir and copy_file_range that cannot see the
        // opener's O_NOATIME
        if attrs.is_noatime() {
            return;
        }
        let now = time_now();
        let a_day_ago = now.0 - 24 * 60 * 60;
        if attrs.last_accessed <= attrs.last_modified
            || attrs.last_accessed <= attrs.last_metadata_changed
            || attrs.last_accessed.0 < a_day_ago
        {
            attrs.last_accessed = now;
            self.write_inode(attrs);
        }
    }

    fn write_inode(&self, inode: &InodeAttributes) {
        let path = Path::new(&self.data_dir)
            .join("inodes")
            .join(inode.inode.to_string());
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        rmp_serde::encode::write(&mut file, inode).unwrap();
    }

    /// Drops one open handle and reclaims the inode if that was the last thing keeping it.
    /// The decrement has to be written back before [`Self::gc_inode`] is consulted, since an
    /// inode with no links is held on disk only by its open handles - an anonymous file from
    /// [`Filesystem::tmpfile`] has never had a link, and a file unlinked while open has lost
    /// its last one, and either way closing the final handle is what makes it collectable
    fn close_handle(&self, attrs: &mut InodeAttributes) {
        attrs.open_file_handles = attrs.open_file_handles.saturating_sub(1);
        self.write_inode(attrs);
        self.gc_inode(attrs);
    }

    // Check whether a file should be removed from storage. Should be called after decrementing
    // the link count, or closing a file handle
    fn gc_inode(&self, inode: &InodeAttributes) -> bool {
        if inode.hardlinks == 0 && inode.open_file_handles == 0 {
            let inode_path = Path::new(&self.data_dir)
                .join("inodes")
                .join(inode.inode.to_string());
            fs::remove_file(inode_path).unwrap();
            let content_path = Path::new(&self.data_dir)
                .join("contents")
                .join(inode.inode.to_string());
            fs::remove_file(content_path).unwrap();

            return true;
        }

        return false;
    }

    /// `uid` and `gid` are the identity the access check runs against, which a caller holding a
    /// write file handle deliberately bypasses; `req` is always the real caller
    fn truncate(
        &self,
        req: &Request,
        inode: INodeNo,
        new_length: u64,
        uid: u32,
        gid: u32,
        kill_suid_gid: bool,
    ) -> Result<InodeAttributes, Errno> {
        if new_length > MAX_FILE_SIZE {
            return Err(Errno::EFBIG);
        }

        let mut attrs = self.get_inode(inode)?;

        // Both flags refuse a truncate: immutable admits no change at all, and append-only
        // admits none that could drop what is already there
        if attrs.is_immutable() || attrs.is_append_only() {
            return Err(Errno::EPERM);
        }

        if !check_access(
            attrs.uid,
            attrs.gid,
            attrs.mode,
            uid,
            gid,
            AccessFlags::W_OK,
        ) {
            return Err(Errno::EACCES);
        }

        let path = self.content_path(inode);
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_len(new_length).unwrap();

        let now = time_now();
        attrs.size = new_length;
        attrs.last_metadata_changed = now;
        attrs.last_modified = now;

        // Clear SETUID & SETGID on truncate, but only when the kernel asks: under killpriv v2
        // it does so exactly when the caller lacks CAP_FSETID
        if kill_suid_gid {
            clear_suid_sgid(&mut attrs, req, Privilege::KnownLacking);
        }
        clear_file_capabilities(&mut attrs);

        self.write_inode(&attrs);

        Ok(attrs)
    }

    fn lookup_name(&self, parent: INodeNo, name: &OsStr) -> Result<InodeAttributes, Errno> {
        let entries = self.get_directory_content(parent)?;
        if let Some((inode, _)) = entries.get(name.as_bytes()) {
            return self.get_inode(INodeNo(*inode));
        }
        return Err(Errno::ENOENT);
    }

    fn insert_link(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        inode: INodeNo,
        kind: FileKind,
    ) -> Result<(), Errno> {
        if self.lookup_name(parent, name).is_ok() {
            return Err(Errno::EEXIST);
        }

        let mut parent_attrs = self.get_inode(parent)?;
        parent_attrs.check_writable()?;

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(req),
            caller_gid(req),
            AccessFlags::W_OK,
        ) {
            return Err(Errno::EACCES);
        }
        let now = time_now();
        parent_attrs.last_modified = now;
        parent_attrs.last_metadata_changed = now;
        self.write_inode(&parent_attrs);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode.0, kind));
        self.write_directory_content(parent, &entries);

        Ok(())
    }
}

impl Filesystem for SimpleFS {
    fn init(
        &mut self,
        _req: &Request,
        #[allow(unused_variables)] config: &mut KernelConfig,
    ) -> io::Result<()> {
        // v2 reports per request whether suid and sgid must go, rather than asking for them to
        // be cleared on every write, chown and truncate as FUSE_HANDLE_KILLPRIV does
        if config
            .add_capabilities(InitFlags::FUSE_HANDLE_KILLPRIV_V2)
            .is_err()
        {
            info!("FUSE_HANDLE_KILLPRIV_V2 not supported");
            self.suid_support = false;
        } else {
            self.killpriv_negotiated = true;
        }

        fs::create_dir_all(Path::new(&self.data_dir).join("inodes")).unwrap();
        fs::create_dir_all(Path::new(&self.data_dir).join("contents")).unwrap();
        if self.get_inode(INodeNo::ROOT).is_err() {
            // Initialize with empty filesystem
            let now = time_now();
            let root = InodeAttributes {
                inode: INodeNo::ROOT.0,
                open_file_handles: 0,
                size: 0,
                last_accessed: now,
                last_modified: now,
                last_metadata_changed: now,
                created: now,
                kind: FileKind::Directory,
                mode: 0o777,
                hardlinks: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0,
                xattrs: BTreeMap::default(),
            };
            self.write_inode(&root);
            let mut entries = BTreeMap::new();
            entries.insert(b".".to_vec(), (INodeNo::ROOT.0, FileKind::Directory));
            self.write_directory_content(INodeNo::ROOT, &entries);
        }
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if name.len() > MAX_NAME_LENGTH as usize {
            reply.error(Errno::ENAMETOOLONG);
            return;
        }
        let parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };
        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::X_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }

        match self.lookup_name(parent, name) {
            Ok(attrs) => reply.entry(
                &Duration::new(0, 0),
                &self.file_attr(attrs),
                fuser::Generation(0),
            ),
            Err(error_code) => reply.error(error_code),
        }
    }

    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {}

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.get_inode(ino) {
            Ok(attrs) => reply.attr(&Duration::new(0, 0), &self.file_attr(attrs)),
            Err(error_code) => reply.error(error_code),
        }
    }

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
        _flags: Option<BsdFileFlags>,
        kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        let mut attrs = match self.get_inode(ino) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        // An immutable inode takes no attribute change at all. An append-only one takes only
        // the timestamp updates that writing it produces, not an explicit time, mode or owner
        if attrs.is_immutable()
            || (attrs.is_append_only()
                && (mode.is_some()
                    || uid.is_some()
                    || gid.is_some()
                    || size.is_some()
                    || matches!(_atime, Some(TimeOrNow::SpecificTime(_)))
                    || matches!(_mtime, Some(TimeOrNow::SpecificTime(_)))))
        {
            reply.error(Errno::EPERM);
            return;
        }

        if let Some(mode) = mode {
            debug!("chmod() called with {ino:?}, {mode:o}");
            #[cfg(target_os = "freebsd")]
            {
                // FreeBSD: sticky bit only valid on directories; otherwise EFTYPE
                if caller_uid(_req) != 0
                    && (mode as u16 & libc::S_ISVTX as u16) != 0
                    && attrs.kind != FileKind::Directory
                {
                    reply.error(Errno::EFTYPE);
                    return;
                }
            }
            if caller_uid(_req) != 0 && caller_uid(_req) != attrs.uid {
                reply.error(Errno::EPERM);
                return;
            }
            if caller_uid(_req) != 0
                && caller_gid(_req) != attrs.gid
                && !get_groups(_req.pid()).contains(&attrs.gid)
            {
                // If SGID is set and the file belongs to a group that the caller is not part of
                // then the SGID bit is suppose to be cleared during chmod
                attrs.mode = (mode & !libc::S_ISGID as u32) as u16;
            } else {
                attrs.mode = mode as u16;
            }
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.attr(&Duration::new(0, 0), &self.file_attr(attrs));
            return;
        }

        if uid.is_some() || gid.is_some() {
            debug!("chown() called with {ino:?} {uid:?} {gid:?}");
            if let Some(gid) = gid {
                // Non-root users can only change gid to a group they're in
                if caller_uid(_req) != 0 && !get_groups(_req.pid()).contains(&gid) {
                    reply.error(Errno::EPERM);
                    return;
                }
            }
            if let Some(uid) = uid {
                if caller_uid(_req) != 0
                    // but no-op changes by the owner are not an error
                    && !(uid == attrs.uid && caller_uid(_req) == attrs.uid)
                {
                    reply.error(Errno::EPERM);
                    return;
                }
            }
            // Only owner may change the group
            if gid.is_some() && caller_uid(_req) != 0 && caller_uid(_req) != attrs.uid {
                reply.error(Errno::EPERM);
                return;
            }

            // Under killpriv v2 the kernel sends this for every chown of a non-directory, so
            // the filesystem no longer has to work out when the bits should go
            if kill_suid_gid {
                clear_suid_sgid(&mut attrs, _req, Privilege::Unknown);
            }
            clear_file_capabilities(&mut attrs);

            if let Some(uid) = uid {
                attrs.uid = uid;
            }
            if let Some(gid) = gid {
                attrs.gid = gid;
            }
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.attr(&Duration::new(0, 0), &self.file_attr(attrs));
            return;
        }

        if let Some(size) = size {
            debug!("truncate() called with {ino:?} {size:?}");
            if let Some(handle) = fh {
                // If the file handle is available, check access locally.
                // This is important as it preserves the semantic that a file handle opened
                // with W_OK will never fail to truncate, even if the file has been subsequently
                // chmod'ed
                if Self::check_file_handle_write(handle.into()) {
                    if let Err(error_code) = self.truncate(_req, ino, size, 0, 0, kill_suid_gid) {
                        reply.error(error_code);
                        return;
                    }
                } else {
                    reply.error(Errno::EACCES);
                    return;
                }
            } else if let Err(error_code) = self.truncate(
                _req,
                ino,
                size,
                caller_uid(_req),
                caller_gid(_req),
                kill_suid_gid,
            ) {
                reply.error(error_code);
                return;
            }
        }

        let now = time_now();
        if let Some(atime) = _atime {
            debug!("utimens() called with {ino:?}, atime={atime:?}");

            if attrs.uid != caller_uid(_req) && caller_uid(_req) != 0 && atime != Now {
                reply.error(Errno::EPERM);
                return;
            }

            if attrs.uid != caller_uid(_req)
                && !check_access(
                    attrs.uid,
                    attrs.gid,
                    attrs.mode,
                    caller_uid(_req),
                    caller_gid(_req),
                    AccessFlags::W_OK,
                )
            {
                reply.error(Errno::EACCES);
                return;
            }

            attrs.last_accessed = match atime {
                TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                Now => now,
            };
            attrs.last_metadata_changed = now;
            self.write_inode(&attrs);
        }
        if let Some(mtime) = _mtime {
            debug!("utimens() called with {ino:?}, mtime={mtime:?}");

            if attrs.uid != caller_uid(_req) && caller_uid(_req) != 0 && mtime != Now {
                reply.error(Errno::EPERM);
                return;
            }

            if attrs.uid != caller_uid(_req)
                && !check_access(
                    attrs.uid,
                    attrs.gid,
                    attrs.mode,
                    caller_uid(_req),
                    caller_gid(_req),
                    AccessFlags::W_OK,
                )
            {
                reply.error(Errno::EACCES);
                return;
            }

            attrs.last_modified = match mtime {
                TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                Now => now,
            };
            attrs.last_metadata_changed = now;
            self.write_inode(&attrs);
        }

        let attrs = self.get_inode(ino).unwrap();
        reply.attr(&Duration::new(0, 0), &self.file_attr(attrs));
        return;
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        debug!("readlink() called on {ino:?}");
        let path = self.content_path(ino);
        match File::open(path) {
            Ok(mut file) => {
                let file_size = file.metadata().unwrap().len();
                let mut buffer = vec![0; file_size as usize];
                file.read_exact(&mut buffer).unwrap();
                if let Ok(mut attrs) = self.get_inode(ino) {
                    self.touch_atime(&mut attrs);
                }
                reply.data(&buffer);
            }
            _ => {
                reply.error(Errno::ENOENT);
            }
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        rdev: u32,
        owner: Owner,
        reply: ReplyEntry,
    ) {
        let file_type = mode & libc::S_IFMT as u32;

        if file_type != libc::S_IFREG as u32
            && file_type != libc::S_IFLNK as u32
            && file_type != libc::S_IFDIR as u32
            && file_type != libc::S_IFCHR as u32
            && file_type != libc::S_IFBLK as u32
            && file_type != libc::S_IFIFO as u32
            && file_type != libc::S_IFSOCK as u32
        {
            warn!("mknod() got a mode with no recognized file type: {mode:o}");
            reply.error(Errno::EPERM);
            return;
        }

        if self.lookup_name(parent, name).is_ok() {
            reply.error(Errno::EEXIST);
            return;
        }

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if let Err(error_code) = parent_attrs.check_writable() {
            reply.error(error_code);
            return;
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }
        let now = time_now();
        parent_attrs.last_modified = now;
        parent_attrs.last_metadata_changed = now;
        self.write_inode(&parent_attrs);

        if caller_uid(_req) != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        #[cfg(target_os = "freebsd")]
        {
            let kind = as_file_kind(mode);
            // FreeBSD: sticky bit only valid on directories; otherwise EFTYPE
            if caller_uid(_req) != 0
                && (mode as u16 & libc::S_ISVTX as u16) != 0
                && kind != FileKind::Directory
            {
                reply.error(Errno::EFTYPE);
                return;
            }
        }

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode: inode.0,
            open_file_handles: 0,
            size: 0,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            created: now,
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: owner.uid,
            gid: creation_gid(&parent_attrs, owner.gid),
            rdev: match as_file_kind(mode) {
                FileKind::CharDevice | FileKind::BlockDevice => rdev,
                // Every other type reports 0, as a local filesystem does
                _ => 0,
            },
            flags: 0,
            xattrs: BTreeMap::default(),
        };
        self.write_inode(&attrs);
        // A fifo, socket or device node holds no data of its own - the kernel services reads
        // and writes without ever reaching this filesystem - but the empty file keeps unlink
        // and the garbage collector uniform across every kind
        File::create(self.content_path(inode)).unwrap();

        if as_file_kind(mode) == FileKind::Directory {
            let mut entries = BTreeMap::new();
            entries.insert(b".".to_vec(), (inode.0, FileKind::Directory));
            entries.insert(b"..".to_vec(), (parent.0, FileKind::Directory));
            self.write_directory_content(inode, &entries);
        }

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode.0, attrs.kind));
        self.write_directory_content(parent, &entries);

        // TODO: implement flags
        reply.entry(
            &Duration::new(0, 0),
            &self.file_attr(attrs),
            fuser::Generation(0),
        );
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        owner: Owner,
        reply: ReplyEntry,
    ) {
        debug!("mkdir() called with {parent:?} {name:?} {mode:o}");
        if self.lookup_name(parent, name).is_ok() {
            reply.error(Errno::EEXIST);
            return;
        }

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if let Err(error_code) = parent_attrs.check_writable() {
            reply.error(error_code);
            return;
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }
        let now = time_now();
        parent_attrs.last_modified = now;
        parent_attrs.last_metadata_changed = now;
        self.write_inode(&parent_attrs);

        if caller_uid(_req) != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
        if parent_attrs.mode & libc::S_ISGID as u16 != 0 {
            mode |= libc::S_ISGID as u32;
        }

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode: inode.0,
            open_file_handles: 0,
            size: u64::from(BLOCK_SIZE),
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            created: now,
            kind: FileKind::Directory,
            mode: self.creation_mode(mode),
            hardlinks: 2, // Directories start with link count of 2, since they have a self link
            uid: owner.uid,
            gid: creation_gid(&parent_attrs, owner.gid),
            rdev: 0,
            flags: 0,
            xattrs: BTreeMap::default(),
        };
        self.write_inode(&attrs);

        let mut entries = BTreeMap::new();
        entries.insert(b".".to_vec(), (inode.0, FileKind::Directory));
        entries.insert(b"..".to_vec(), (parent.0, FileKind::Directory));
        self.write_directory_content(inode, &entries);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode.0, FileKind::Directory));
        self.write_directory_content(parent, &entries);

        reply.entry(
            &Duration::new(0, 0),
            &self.file_attr(attrs),
            fuser::Generation(0),
        );
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        debug!("unlink() called with {parent:?} {name:?}");
        let mut attrs = match self.lookup_name(parent, name) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if let Err(error_code) = parent_attrs
            .check_removable()
            .and_then(|()| attrs.check_removable())
        {
            reply.error(error_code);
            return;
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }

        let uid = caller_uid(_req);
        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && uid != 0
            && uid != parent_attrs.uid
            && uid != attrs.uid
        {
            reply.error(Errno::EACCES);
            return;
        }

        let now = time_now();
        parent_attrs.last_metadata_changed = now;
        parent_attrs.last_modified = now;
        self.write_inode(&parent_attrs);

        attrs.hardlinks -= 1;
        attrs.last_metadata_changed = now;
        self.write_inode(&attrs);
        self.gc_inode(&attrs);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, &entries);

        reply.ok();
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        debug!("rmdir() called with {parent:?} {name:?}");
        let mut attrs = match self.lookup_name(parent, name) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        // Ahead of the emptiness check, as Linux tests the flags before it reaches the
        // filesystem at all: an immutable directory refuses the removal whatever is in it
        if let Err(error_code) = parent_attrs
            .check_removable()
            .and_then(|()| attrs.check_removable())
        {
            reply.error(error_code);
            return;
        }

        // Directories always have a self and parent link
        if self
            .get_directory_content(INodeNo(attrs.inode))
            .unwrap()
            .len()
            > 2
        {
            reply.error(Errno::ENOTEMPTY);
            return;
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }

        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && caller_uid(_req) != 0
            && caller_uid(_req) != parent_attrs.uid
            && caller_uid(_req) != attrs.uid
        {
            reply.error(Errno::EACCES);
            return;
        }

        let now = time_now();
        parent_attrs.last_metadata_changed = now;
        parent_attrs.last_modified = now;
        self.write_inode(&parent_attrs);

        attrs.hardlinks = 0;
        attrs.last_metadata_changed = now;
        self.write_inode(&attrs);
        self.gc_inode(&attrs);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, &entries);

        reply.ok();
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        owner: Owner,
        reply: ReplyEntry,
    ) {
        debug!("symlink() called with {parent:?} {link_name:?} {target:?}");
        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if let Err(error_code) = parent_attrs.check_writable() {
            reply.error(error_code);
            return;
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }
        let now = time_now();
        parent_attrs.last_modified = now;
        parent_attrs.last_metadata_changed = now;
        self.write_inode(&parent_attrs);

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode: inode.0,
            open_file_handles: 0,
            size: target.as_os_str().as_bytes().len() as u64,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            created: now,
            kind: FileKind::Symlink,
            mode: 0o777,
            hardlinks: 1,
            uid: owner.uid,
            gid: creation_gid(&parent_attrs, owner.gid),
            rdev: 0,
            flags: 0,
            xattrs: BTreeMap::default(),
        };

        if let Err(error_code) = self.insert_link(_req, parent, link_name, inode, FileKind::Symlink)
        {
            reply.error(error_code);
            return;
        }
        self.write_inode(&attrs);

        let path = self.content_path(inode);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(target.as_os_str().as_bytes()).unwrap();

        reply.entry(
            &Duration::new(0, 0),
            &self.file_attr(attrs),
            fuser::Generation(0),
        );
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        owner: Option<Owner>,
        reply: ReplyEmpty,
    ) {
        debug!(
            "rename() called with: source {parent:?} {name:?}, \
            destination {newparent:?} {newname:?}, flags {flags:#b}",
        );
        let mut inode_attrs = match self.lookup_name(parent, name) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }

        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && caller_uid(_req) != 0
            && caller_uid(_req) != parent_attrs.uid
            && caller_uid(_req) != inode_attrs.uid
        {
            reply.error(Errno::EACCES);
            return;
        }

        let mut new_parent_attrs = match self.get_inode(newparent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            new_parent_attrs.uid,
            new_parent_attrs.gid,
            new_parent_attrs.mode,
            caller_uid(_req),
            caller_gid(_req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }

        // "Sticky bit" handling in new_parent
        if new_parent_attrs.mode & libc::S_ISVTX as u16 != 0 {
            if let Ok(existing_attrs) = self.lookup_name(newparent, newname) {
                if caller_uid(_req) != 0
                    && caller_uid(_req) != new_parent_attrs.uid
                    && caller_uid(_req) != existing_attrs.uid
                {
                    reply.error(Errno::EACCES);
                    return;
                }
            }
        }

        // A rename removes an entry from one directory and creates one in another, so every
        // inode it touches has to allow its side of that
        let destination = self.lookup_name(newparent, newname);
        if let Err(error_code) = parent_attrs
            .check_removable()
            .and_then(|()| inode_attrs.check_removable())
            .and_then(|()| new_parent_attrs.check_writable())
            .and_then(|()| {
                destination
                    .as_ref()
                    .map_or(Ok(()), InodeAttributes::check_removable)
            })
        {
            reply.error(error_code);
            return;
        }

        // Linux's RENAME_EXCHANGE and macOS's RENAME_SWAP both mean: atomically exchange the
        // two entries instead of replacing the destination. Linux's RENAME_NOREPLACE and
        // macOS's RENAME_EXCL both mean: fail instead of replacing an existing destination
        #[cfg(target_os = "linux")]
        let (exchange, no_replace) = (
            flags.contains(RenameFlags::RENAME_EXCHANGE),
            flags.contains(RenameFlags::RENAME_NOREPLACE),
        );
        #[cfg(target_os = "macos")]
        let (exchange, no_replace) = (
            flags.contains(RenameFlags::RENAME_SWAP),
            flags.contains(RenameFlags::RENAME_EXCL),
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let (exchange, no_replace) = (false, false);

        // Leaving a whiteout behind is Linux-only; macOS has no equivalent
        #[cfg(target_os = "linux")]
        let whiteout = flags.contains(RenameFlags::RENAME_WHITEOUT);
        #[cfg(not(target_os = "linux"))]
        let whiteout = false;

        // Exchanging and refusing to replace are contradictory: renameat2(2) and
        // renamex_np(2) both reject the combination
        if exchange && no_replace {
            reply.error(Errno::EINVAL);
            return;
        }

        // An exchange leaves nothing behind to white out, so renameat2(2) refuses the pair
        if exchange && whiteout {
            reply.error(Errno::EINVAL);
            return;
        }

        if exchange {
            let mut new_inode_attrs = match self.lookup_name(newparent, newname) {
                Ok(attrs) => attrs,
                Err(error_code) => {
                    reply.error(error_code);
                    return;
                }
            };

            let mut entries = self.get_directory_content(newparent).unwrap();
            entries.insert(
                newname.as_bytes().to_vec(),
                (inode_attrs.inode, inode_attrs.kind),
            );
            self.write_directory_content(newparent, &entries);

            let mut entries = self.get_directory_content(parent).unwrap();
            entries.insert(
                name.as_bytes().to_vec(),
                (new_inode_attrs.inode, new_inode_attrs.kind),
            );
            self.write_directory_content(parent, &entries);

            let now = time_now();
            parent_attrs.last_metadata_changed = now;
            parent_attrs.last_modified = now;
            self.write_inode(&parent_attrs);
            new_parent_attrs.last_metadata_changed = now;
            new_parent_attrs.last_modified = now;
            self.write_inode(&new_parent_attrs);
            inode_attrs.last_metadata_changed = now;
            self.write_inode(&inode_attrs);
            new_inode_attrs.last_metadata_changed = now;
            self.write_inode(&new_inode_attrs);

            if inode_attrs.kind == FileKind::Directory {
                let mut entries = self
                    .get_directory_content(INodeNo(inode_attrs.inode))
                    .unwrap();
                entries.insert(b"..".to_vec(), (newparent.0, FileKind::Directory));
                self.write_directory_content(INodeNo(inode_attrs.inode), &entries);
            }
            if new_inode_attrs.kind == FileKind::Directory {
                let mut entries = self
                    .get_directory_content(INodeNo(new_inode_attrs.inode))
                    .unwrap();
                entries.insert(b"..".to_vec(), (parent.0, FileKind::Directory));
                self.write_directory_content(INodeNo(new_inode_attrs.inode), &entries);
            }

            reply.ok();
            return;
        }

        if no_replace && self.lookup_name(newparent, newname).is_ok() {
            reply.error(Errno::EEXIST);
            return;
        }

        // Only overwrite an existing directory if it's empty
        if let Ok(new_name_attrs) = self.lookup_name(newparent, newname) {
            if new_name_attrs.kind == FileKind::Directory
                && self
                    .get_directory_content(INodeNo(new_name_attrs.inode))
                    .unwrap()
                    .len()
                    > 2
            {
                reply.error(Errno::ENOTEMPTY);
                return;
            }
        }

        // Only move an existing directory to a new parent, if we have write access to it,
        // because that will change the ".." link in it
        if inode_attrs.kind == FileKind::Directory
            && parent != newparent
            && !check_access(
                inode_attrs.uid,
                inode_attrs.gid,
                inode_attrs.mode,
                caller_uid(_req),
                caller_gid(_req),
                AccessFlags::W_OK,
            )
        {
            reply.error(Errno::EACCES);
            return;
        }

        let now = time_now();

        // If target already exists decrement its hardlink count
        if let Ok(mut existing_inode_attrs) = self.lookup_name(newparent, newname) {
            let mut entries = self.get_directory_content(newparent).unwrap();
            entries.remove(newname.as_bytes());
            self.write_directory_content(newparent, &entries);

            if existing_inode_attrs.kind == FileKind::Directory {
                existing_inode_attrs.hardlinks = 0;
            } else {
                existing_inode_attrs.hardlinks -= 1;
            }
            existing_inode_attrs.last_metadata_changed = now;
            self.write_inode(&existing_inode_attrs);
            self.gc_inode(&existing_inode_attrs);
        }

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.remove(name.as_bytes());
        // A whiteout rename puts a placeholder where the entry was, so a filesystem stacked
        // above this one can tell "removed here" apart from "never existed". The kernel's own
        // is a character device with device number 0 and no permission bits, which is not a
        // node anything can be read from or written to
        if whiteout {
            // The kernel names the owner for exactly this case: a rename creates an inode
            // only here, and this is the only rename it sends ids for
            let Some(owner) = owner else {
                reply.error(Errno::EIO);
                return;
            };
            let whiteout_inode = self.allocate_next_inode();
            let whiteout_attrs = InodeAttributes {
                inode: whiteout_inode.0,
                open_file_handles: 0,
                size: 0,
                last_accessed: now,
                last_modified: now,
                last_metadata_changed: now,
                created: now,
                kind: FileKind::CharDevice,
                mode: 0,
                hardlinks: 1,
                uid: owner.uid,
                gid: creation_gid(&parent_attrs, owner.gid),
                rdev: 0,
                flags: 0,
                xattrs: BTreeMap::default(),
            };
            self.write_inode(&whiteout_attrs);
            File::create(self.content_path(whiteout_inode)).unwrap();
            entries.insert(
                name.as_bytes().to_vec(),
                (whiteout_attrs.inode, whiteout_attrs.kind),
            );
        }
        self.write_directory_content(parent, &entries);

        let mut entries = self.get_directory_content(newparent).unwrap();
        entries.insert(
            newname.as_bytes().to_vec(),
            (inode_attrs.inode, inode_attrs.kind),
        );
        self.write_directory_content(newparent, &entries);

        parent_attrs.last_metadata_changed = now;
        parent_attrs.last_modified = now;
        self.write_inode(&parent_attrs);
        new_parent_attrs.last_metadata_changed = now;
        new_parent_attrs.last_modified = now;
        self.write_inode(&new_parent_attrs);
        inode_attrs.last_metadata_changed = now;
        self.write_inode(&inode_attrs);

        if inode_attrs.kind == FileKind::Directory {
            let mut entries = self
                .get_directory_content(INodeNo(inode_attrs.inode))
                .unwrap();
            entries.insert(b"..".to_vec(), (newparent.0, FileKind::Directory));
            self.write_directory_content(INodeNo(inode_attrs.inode), &entries);
        }

        reply.ok();
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        debug!("link() called for {ino}, {newparent}, {newname:?}");
        let mut attrs = match self.get_inode(ino) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };
        if let Err(error_code) = attrs
            .check_removable()
            .and_then(|()| self.insert_link(_req, newparent, newname, ino, attrs.kind))
        {
            reply.error(error_code);
        } else {
            attrs.hardlinks += 1;
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.entry(
                &Duration::new(0, 0),
                &self.file_attr(attrs),
                fuser::Generation(0),
            );
        }
    }

    fn open(
        &self,
        _req: &Request,
        _ino: INodeNo,
        flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        debug!("open() called for {_ino:?}");
        let (access_mask, read, write) = match flags.acc_mode() {
            OpenAccMode::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags.0 & libc::O_TRUNC != 0 {
                    reply.error(Errno::EACCES);
                    return;
                }
                if flags.0 & FMODE_EXEC != 0 {
                    // Open is from internal exec syscall
                    (libc::X_OK, true, false)
                } else {
                    (libc::R_OK, true, false)
                }
            }
            OpenAccMode::O_WRONLY => (libc::W_OK, false, true),
            OpenAccMode::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
        };

        match self.get_inode(_ino) {
            Ok(mut attr) => {
                // Opening for write is where both flags bite. Linux checks here rather than on
                // every write, so a file made immutable afterwards stays writable through a
                // descriptor that was already open
                if write && attr.is_immutable() {
                    reply.error(Errno::EPERM);
                    return;
                }
                if attr.is_append_only()
                    && ((write && flags.0 & libc::O_APPEND == 0) || flags.0 & libc::O_TRUNC != 0)
                {
                    reply.error(Errno::EPERM);
                    return;
                }
                if check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    caller_uid(_req),
                    caller_gid(_req),
                    AccessFlags::from_bits_retain(access_mask),
                ) {
                    attr.open_file_handles += 1;
                    self.write_inode(&attr);
                    let open_flags = if self.direct_io {
                        FopenFlags::FOPEN_DIRECT_IO
                    } else {
                        FopenFlags::empty()
                    };
                    reply.opened(
                        FileHandle(self.allocate_next_file_handle(read, write)),
                        open_flags,
                    );
                } else {
                    reply.error(Errno::EACCES);
                }
                return;
            }
            Err(error_code) => reply.error(error_code),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        debug!("read() called on {ino:?} offset={offset:?} size={size:?}");
        if !Self::check_file_handle_read(fh.into()) {
            reply.error(Errno::EACCES);
            return;
        }

        let path = self.content_path(ino);
        match File::open(path) {
            Ok(file) => {
                let file_size = file.metadata().unwrap().len();
                // Could underflow if file length is less than local_start
                let read_size = min(size, file_size.saturating_sub(offset as u64) as u32);

                let mut buffer = vec![0; read_size as usize];
                file.read_exact_at(&mut buffer, offset as u64).unwrap();
                // A reader that asked for O_NOATIME wants to leave no trace, and a read
                // request carries the flag, so it can be honored here. The flag is Linux's;
                // neither macOS nor FreeBSD defines it
                #[cfg(target_os = "linux")]
                let no_atime = _flags.0 & libc::O_NOATIME != 0;
                #[cfg(not(target_os = "linux"))]
                let no_atime = false;
                if !no_atime {
                    if let Ok(mut attrs) = self.get_inode(ino) {
                        self.touch_atime(&mut attrs);
                    }
                }
                reply.data(&buffer);
            }
            _ => {
                reply.error(Errno::ENOENT);
            }
        }
    }

    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        debug!("write() called with {:?} size={:?}", ino, data.len());
        if !Self::check_file_handle_write(fh.into()) {
            reply.error(Errno::EACCES);
            return;
        }

        let path = self.content_path(ino);
        match OpenOptions::new().write(true).open(path) {
            Ok(mut file) => {
                let Ok(offset_usize): Result<usize, _> = offset.try_into() else {
                    reply.error(Errno::EFBIG);
                    return;
                };
                let Some(end_offset) = data.len().checked_add(offset_usize) else {
                    reply.error(Errno::EFBIG);
                    return;
                };

                file.seek(SeekFrom::Start(offset)).unwrap();
                file.write_all(data).unwrap();
                // Release the descriptor before opening the inode. Near RLIMIT_NOFILE this write
                // may hold the last one, and get_inode() reports the resulting EMFILE as ENOENT,
                // which would fail a write whose data already landed.
                drop(file);

                // Read the inode only once the data is written. Holding a copy across the write
                // would let this write back a record that a setattr() completing in the meantime
                // had already updated. Contents and metadata are separate files, so the inode can
                // be unreadable even though the write itself succeeded.
                let mut attrs = match self.get_inode(ino) {
                    Ok(attrs) => attrs,
                    Err(error_code) => {
                        reply.error(error_code);
                        return;
                    }
                };
                let now = time_now();
                attrs.last_metadata_changed = now;
                attrs.last_modified = now;
                if end_offset > attrs.size as usize {
                    attrs.size = end_offset as u64;
                }
                // Only killpriv v2 sets this on a buffered write, which is why honoring it
                // requires negotiating v2 rather than FUSE_HANDLE_KILLPRIV
                if write_flags.contains(WriteFlags::FUSE_WRITE_KILL_SUIDGID) {
                    clear_suid_sgid(&mut attrs, req, Privilege::KnownLacking);
                }
                clear_file_capabilities(&mut attrs);
                self.write_inode(&attrs);

                reply.written(data.len() as u32);
            }
            _ => {
                reply.error(Errno::EBADF);
            }
        }
    }

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
        if let Ok(mut attrs) = self.get_inode(_ino) {
            self.close_handle(&mut attrs);
        }
        reply.ok();
    }

    fn opendir(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        debug!("opendir() called on {_ino:?}");
        let (access_mask, read, write) = match _flags.acc_mode() {
            OpenAccMode::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if _flags.0 & libc::O_TRUNC != 0 {
                    reply.error(Errno::EACCES);
                    return;
                }
                (libc::R_OK, true, false)
            }
            OpenAccMode::O_WRONLY => (libc::W_OK, false, true),
            OpenAccMode::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
        };

        match self.get_inode(_ino) {
            Ok(mut attr) => {
                if check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    caller_uid(_req),
                    caller_gid(_req),
                    AccessFlags::from_bits_retain(access_mask),
                ) {
                    attr.open_file_handles += 1;
                    self.write_inode(&attr);
                    let open_flags = if self.direct_io {
                        FopenFlags::FOPEN_DIRECT_IO
                    } else {
                        FopenFlags::empty()
                    };
                    reply.opened(
                        FileHandle(self.allocate_next_file_handle(read, write)),
                        open_flags,
                    );
                } else {
                    reply.error(Errno::EACCES);
                }
                return;
            }
            Err(error_code) => reply.error(error_code),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir() called with {ino:?}");
        let entries = match self.get_directory_content(ino) {
            Ok(entries) => entries,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };
        if let Ok(mut attrs) = self.get_inode(ino) {
            self.touch_atime(&mut attrs);
        }

        for (index, entry) in entries.iter().skip(offset as usize).enumerate() {
            let (name, (inode, file_type)) = entry;

            let buffer_full: bool = reply.add(
                INodeNo(*inode),
                offset + index as u64 + 1,
                (*file_type).into(),
                OsStr::from_bytes(name),
            );

            if buffer_full {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut attrs) = self.get_inode(_ino) {
            self.close_handle(&mut attrs);
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        // Pass through the backing directory's capacity, rescaled to this filesystem's block
        // size. Callers that size their work to the free space, `df` among them, read this
        let stat = match nix::sys::statvfs::statvfs(Path::new(&self.data_dir)) {
            Ok(stat) => stat,
            Err(error) => {
                reply.error(io::Error::from(error).into());
                return;
            }
        };
        // Widened explicitly: statvfs reports these in types whose width varies by platform,
        // 64 bits on Linux and 32 on macOS
        let fragment_size = stat.fragment_size() as u64;
        let in_blocks = |count: u64| count.saturating_mul(fragment_size) / u64::from(BLOCK_SIZE);
        // Every inode here costs two in the backing directory, one under `inodes` for the
        // metadata and one under `contents` for the data, so the backing store runs out of
        // them twice as fast as a pass-through count would suggest
        let in_inodes = |count: u64| count / 2;
        reply.statfs(
            in_blocks(stat.blocks() as u64),
            in_blocks(stat.blocks_free() as u64),
            in_blocks(stat.blocks_available() as u64),
            in_inodes(stat.files() as u64),
            in_inodes(stat.files_free() as u64),
            BLOCK_SIZE,
            MAX_NAME_LENGTH,
            BLOCK_SIZE,
        );
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut attrs) = self.get_inode(ino) {
            if let Err(error) = xattr_access_check(name.as_bytes(), libc::W_OK, &attrs, _req) {
                reply.error(error);
                return;
            }

            attrs
                .xattrs
                .insert(name.as_bytes().to_vec(), _value.to_vec());
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.ok();
        } else {
            reply.error(Errno::EBADF);
        }
    }

    fn getxattr(
        &self,
        request: &Request,
        inode: INodeNo,
        key: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        if let Ok(attrs) = self.get_inode(inode) {
            if let Err(error) = xattr_access_check(key.as_bytes(), libc::R_OK, &attrs, request) {
                reply.error(error);
                return;
            }

            if let Some(data) = attrs.xattrs.get(key.as_bytes()) {
                if size == 0 {
                    reply.size(data.len() as u32);
                } else if data.len() <= size as usize {
                    reply.data(data);
                } else {
                    reply.error(Errno::ERANGE);
                }
            } else {
                #[cfg(target_os = "linux")]
                reply.error(Errno::ENODATA);
                #[cfg(not(target_os = "linux"))]
                reply.error(Errno::ENOATTR);
            }
        } else {
            reply.error(Errno::EBADF);
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        if let Ok(attrs) = self.get_inode(ino) {
            let mut bytes = vec![];
            // Convert to concatenated null-terminated strings
            for key in attrs.xattrs.keys() {
                bytes.extend(key);
                bytes.push(0);
            }
            if size == 0 {
                reply.size(bytes.len() as u32);
            } else if bytes.len() <= size as usize {
                reply.data(&bytes);
            } else {
                reply.error(Errno::ERANGE);
            }
        } else {
            reply.error(Errno::EBADF);
        }
    }

    fn removexattr(&self, request: &Request, inode: INodeNo, key: &OsStr, reply: ReplyEmpty) {
        if let Ok(mut attrs) = self.get_inode(inode) {
            // The kernel drops `security.capability` on behalf of whoever is writing the file,
            // and sends that removal under their credentials rather than its own. Refusing it
            // because they are not root fails the operation it was part of - a `fallocate` by
            // an unprivileged user returns EPERM without ever reaching this filesystem. So
            // this one key is removable by anyone: doing so only ever takes privilege away.
            // Setting it still needs root, as it does for any other `security.*` key
            if key.as_bytes() != b"security.capability" {
                if let Err(error) = xattr_access_check(key.as_bytes(), libc::W_OK, &attrs, request)
                {
                    reply.error(error);
                    return;
                }
            }

            if attrs.xattrs.remove(key.as_bytes()).is_none() {
                #[cfg(target_os = "linux")]
                reply.error(Errno::ENODATA);
                #[cfg(not(target_os = "linux"))]
                reply.error(Errno::ENOATTR);
                return;
            }
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.ok();
        } else {
            reply.error(Errno::EBADF);
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        debug!("access() called with {ino:?} {mask:?}");
        match self.get_inode(ino) {
            Ok(attr) => {
                if check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    caller_uid(_req),
                    caller_gid(_req),
                    mask,
                ) {
                    reply.ok();
                } else {
                    reply.error(Errno::EACCES);
                }
            }
            Err(error_code) => reply.error(error_code),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        flags: i32,
        _kill_suid_gid: bool,
        owner: Owner,
        reply: ReplyCreate,
    ) {
        debug!("create() called with {parent:?} {name:?}");
        if self.lookup_name(parent, name).is_ok() {
            reply.error(Errno::EEXIST);
            return;
        }

        let (read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if let Err(error_code) = parent_attrs.check_writable() {
            reply.error(error_code);
            return;
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(req),
            caller_gid(req),
            AccessFlags::W_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }
        let now = time_now();
        parent_attrs.last_modified = now;
        parent_attrs.last_metadata_changed = now;
        self.write_inode(&parent_attrs);

        if caller_uid(req) != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        #[cfg(target_os = "freebsd")]
        {
            let kind = as_file_kind(mode);
            // FreeBSD: sticky bit only valid on directories; otherwise EFTYPE
            if caller_uid(req) != 0
                && (mode as u16 & libc::S_ISVTX as u16) != 0
                && kind != FileKind::Directory
            {
                reply.error(Errno::EFTYPE);
                return;
            }
        }

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode: inode.0,
            open_file_handles: 1,
            size: 0,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            created: now,
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: owner.uid,
            gid: creation_gid(&parent_attrs, owner.gid),
            rdev: 0,
            flags: 0,
            xattrs: BTreeMap::default(),
        };
        self.write_inode(&attrs);
        File::create(self.content_path(inode)).unwrap();

        if as_file_kind(mode) == FileKind::Directory {
            let mut entries = BTreeMap::new();
            entries.insert(b".".to_vec(), (inode.0, FileKind::Directory));
            entries.insert(b"..".to_vec(), (parent.0, FileKind::Directory));
            self.write_directory_content(inode, &entries);
        }

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode.0, attrs.kind));
        self.write_directory_content(parent, &entries);

        // TODO: implement flags
        reply.created(
            &Duration::new(0, 0),
            &self.file_attr(attrs),
            fuser::Generation(0),
            FileHandle(self.allocate_next_file_handle(read, write)),
            FopenFlags::empty(),
        );
    }

    /// Answers `statx(2)`, which differs from `getattr()` in carrying a creation time. That
    /// is the whole reason to implement it: `fuse_attr` has no field for one on Linux, so
    /// without this the kernel reports whatever it last cached
    #[cfg(target_os = "linux")]
    fn statx(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        _flags: u32,
        _mask: fuser::StatxMask,
        reply: fuser::ReplyStatx,
    ) {
        debug!("statx() called with {ino:?}");
        let attrs = match self.get_inode(ino) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        // The inode flags this filesystem honors, in the encoding statx uses. The kernel
        // discards them, so `chattr +i` stays invisible to statx(2) whatever is reported here
        // - see StatxAttr::attributes. Filled in because that is what the field is for, and
        // so nothing has to change should the kernel start reading it
        let mut attributes = fuser::StatxAttributes::empty();
        attributes.set(fuser::StatxAttributes::IMMUTABLE, attrs.is_immutable());
        attributes.set(fuser::StatxAttributes::APPEND, attrs.is_append_only());
        attributes.set(
            fuser::StatxAttributes::NODUMP,
            attrs.flags & FS_NODUMP_FL != 0,
        );

        let btime = system_time_from_time(attrs.created.0, attrs.created.1);
        reply.statx(
            &Duration::new(0, 0),
            &fuser::StatxAttr {
                btime: Some(btime),
                attributes,
                // The three above are the ones this filesystem can speak to. Leaving the rest
                // out is what tells a caller "cannot say" rather than "not set"
                attributes_mask: fuser::StatxAttributes::IMMUTABLE
                    | fuser::StatxAttributes::APPEND
                    | fuser::StatxAttributes::NODUMP,
                ..self.file_attr(attrs).into()
            },
        );
    }

    /// Serves the four ioctls the kernel turns chattr(1) and lsattr(1) into. The kernel does
    /// the ownership and `CAP_LINUX_IMMUTABLE` checks before sending them, so all that is left
    /// here is to store the flags and to refuse the ones this filesystem does not honor
    #[cfg(target_os = "linux")]
    fn ioctl(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: fuser::IoctlFlags,
        cmd: u32,
        in_data: &[u8],
        _out_size: u32,
        reply: fuser::ReplyIoctl,
    ) {
        let mut attrs = match self.get_inode(ino) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        // Both setters arrive as the full new flag set, not as a delta
        let new_flags = match cmd {
            FS_IOC_GETFLAGS => {
                reply.ioctl(0, &attrs.flags.to_ne_bytes());
                return;
            }
            FS_IOC_FSGETXATTR => {
                let mut fsxattr = [0; FSXATTR_SIZE];
                fsxattr[..size_of::<u32>()]
                    .copy_from_slice(&xflags_from_flags(attrs.flags).to_ne_bytes());
                reply.ioctl(0, &fsxattr);
                return;
            }
            FS_IOC_SETFLAGS => {
                let Ok(requested) = in_data.try_into().map(u32::from_ne_bytes) else {
                    reply.error(Errno::EINVAL);
                    return;
                };
                if requested & !SUPPORTED_FS_FLAGS != 0 {
                    reply.error(Errno::EOPNOTSUPP);
                    return;
                }
                requested
            }
            FS_IOC_FSSETXATTR => {
                if in_data.len() != FSXATTR_SIZE {
                    reply.error(Errno::EINVAL);
                    return;
                }
                let xflags = u32::from_ne_bytes(in_data[..size_of::<u32>()].try_into().unwrap());
                let Some(flags) = flags_from_xflags(xflags) else {
                    reply.error(Errno::EOPNOTSUPP);
                    return;
                };
                flags
            }
            _ => {
                reply.error(Errno::ENOTTY);
                return;
            }
        };

        if new_flags != attrs.flags {
            attrs.flags = new_flags;
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
        }
        reply.ioctl(0, &[]);
    }

    /// Creates a file that no name reaches, for `open(..., O_TMPFILE)`. It belongs to
    /// `parent`'s directory - that is where its space is accounted, and where it will live if
    /// `link()` later gives it a name - but no entry points at it, so the descriptor replied
    /// with here is the only way to it. Answering at all is what keeps the kernel offering
    /// O_TMPFILE on this connection: the default ENOSYS turns it off permanently
    fn tmpfile(
        &self,
        req: &Request,
        parent: INodeNo,
        mut mode: u32,
        _umask: u32,
        flags: i32,
        _kill_suid_gid: bool,
        owner: Owner,
        reply: ReplyCreate,
    ) {
        debug!("tmpfile() called with {parent:?} {mode:o}");
        let (read, write) = match flags & libc::O_ACCMODE {
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // An anonymous file that cannot be written is of no use, and the kernel rejects
            // the combination before it reaches a filesystem
            _ => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        let parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if parent_attrs.kind != FileKind::Directory {
            reply.error(Errno::ENOTDIR);
            return;
        }

        // The directory has to be writable even though nothing is written to it, and
        // searchable even though nothing is looked up in it: `vfs_tmpfile` asks its own
        // filesystems for `MAY_WRITE | MAY_EXEC`. The directory is this request's operand
        // rather than a component of a path, so no lookup has passed through it and nothing
        // the kernel has already checked implies either
        if let Err(error_code) = parent_attrs.check_writable() {
            reply.error(error_code);
            return;
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            caller_uid(req),
            caller_gid(req),
            AccessFlags::W_OK | AccessFlags::X_OK,
        ) {
            reply.error(Errno::EACCES);
            return;
        }

        // The parent's timestamps are left alone, since no entry is added to it

        if caller_uid(req) != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        let now = time_now();
        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode: inode.0,
            open_file_handles: 1,
            size: 0,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            created: now,
            // The kernel only ever asks for a regular file here
            kind: FileKind::File,
            mode: self.creation_mode(mode),
            // What makes it anonymous. Closing the last handle without linking it collects it,
            // and link() takes it from here to 1
            hardlinks: 0,
            uid: owner.uid,
            gid: creation_gid(&parent_attrs, owner.gid),
            rdev: 0,
            flags: 0,
            xattrs: BTreeMap::default(),
        };
        self.write_inode(&attrs);
        File::create(self.content_path(inode)).unwrap();

        reply.created(
            &Duration::new(0, 0),
            &self.file_attr(attrs),
            fuser::Generation(0),
            FileHandle(self.allocate_next_file_handle(read, write)),
            FopenFlags::empty(),
        );
    }

    #[cfg(target_os = "linux")]
    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let attrs = match self.get_inode(ino) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };
        // Preallocation past the end is the one mode an append-only file accepts, since it
        // adds space without touching what is there. An immutable one accepts none
        if attrs.is_immutable()
            || (attrs.is_append_only() && mode & !libc::FALLOC_FL_KEEP_SIZE != 0)
        {
            reply.error(Errno::EPERM);
            return;
        }

        let path = self.content_path(ino);

        // A filesystem knows roughly what it has and refuses an impossible request outright.
        // Handing it to the backing store instead fills the disk before failing, and this
        // filesystem cannot write even its own metadata once that has happened.
        //
        // The whole range is charged for, without crediting what the file already occupies.
        // Only the blocks inside the requested range are free to reuse, and working out which
        // those are needs a SEEK_HOLE/SEEK_DATA walk of the range. Crediting the file's total
        // block count instead would let through exactly what this rejects: a 1 GiB file whose
        // blocks all sit below the offset can ask for another 1 GiB on a device with less than
        // that free. Erring towards ENOSPC costs a preallocation that would have fit.
        //
        // The modes that give space back are exempt, since they need none to succeed. Only
        // punching can arrive here today - the FUSE kernel driver forwards KEEP_SIZE,
        // PUNCH_HOLE and ZERO_RANGE and refuses the rest before the filesystem sees them -
        // but the condition is written about what the modes mean rather than about what the
        // driver currently sends
        const FREES_SPACE: i32 = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_COLLAPSE_RANGE;
        if mode & FREES_SPACE == 0 && !self.backing_store_can_take(offset, length) {
            reply.error(Errno::ENOSPC);
            return;
        }

        match OpenOptions::new().write(true).open(&path) {
            Ok(file) => {
                // Must not consume `file`, otherwise its descriptor is leaked. Tests that punch
                // thousands of holes exhaust RLIMIT_NOFILE within a single run.
                let result = unsafe {
                    libc::fallocate64(file.as_raw_fd(), mode, offset as i64, length as i64)
                };
                if result < 0 {
                    reply.error(io::Error::last_os_error().into());
                    return;
                }
                let mut attrs = self.get_inode(ino).unwrap();
                // Every fallocate mode changes the file, so the times move even when the size
                // is pinned: a punch-hole rewrites content, and preallocation commits blocks
                let now = time_now();
                attrs.last_metadata_changed = now;
                attrs.last_modified = now;
                if mode & libc::FALLOC_FL_KEEP_SIZE == 0 && offset + length > attrs.size {
                    attrs.size = (offset + length) as u64;
                }
                if self.killpriv_negotiated {
                    clear_privileges_unprompted(&mut attrs, _req);
                }
                self.write_inode(&attrs);
                reply.ok();
            }
            _ => {
                reply.error(Errno::ENOENT);
            }
        }
    }

    fn copy_file_range(
        &self,
        _req: &Request,
        src_inode: INodeNo,
        src_fh: FileHandle,
        src_offset: u64,
        dest_inode: INodeNo,
        dest_fh: FileHandle,
        dest_offset: u64,
        size: u64,
        _flags: fuser::CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        debug!(
            "copy_file_range() called with src=({src_fh}, {src_inode}, {src_offset}) dest=({dest_fh}, {dest_inode}, {dest_offset}) size={size}"
        );
        if !Self::check_file_handle_read(src_fh.into()) {
            reply.error(Errno::EACCES);
            return;
        }
        if !Self::check_file_handle_write(dest_fh.into()) {
            reply.error(Errno::EACCES);
            return;
        }
        // Checked on every call rather than at open, which is where the flags are otherwise
        // enforced: `generic_copy_file_checks` rejects an immutable destination each time
        match self.get_inode(dest_inode) {
            Ok(attrs) => {
                if let Err(error_code) = attrs.check_writable() {
                    reply.error(error_code);
                    return;
                }
            }
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        }

        let src_path = self.content_path(src_inode);
        match File::open(src_path) {
            Ok(file) => {
                let file_size = file.metadata().unwrap().len();
                // Could underflow if file length is less than local_start
                let read_size = min(size, file_size.saturating_sub(src_offset));

                let mut data = vec![0; read_size as usize];
                file.read_exact_at(&mut data, src_offset).unwrap();
                // Copying reads the source, and Linux moves its atime accordingly
                if let Ok(mut src_attrs) = self.get_inode(src_inode) {
                    self.touch_atime(&mut src_attrs);
                }

                let dest_path = self.content_path(dest_inode);
                match OpenOptions::new().write(true).open(dest_path) {
                    Ok(mut file) => {
                        file.seek(SeekFrom::Start(dest_offset)).unwrap();
                        file.write_all(&data).unwrap();

                        let mut attrs = self.get_inode(dest_inode).unwrap();
                        let now = time_now();
                        attrs.last_metadata_changed = now;
                        attrs.last_modified = now;
                        let Ok(dest_offset_usize): Result<usize, _> = dest_offset.try_into() else {
                            reply.error(Errno::EFBIG);
                            return;
                        };
                        let Some(end_offset) = data.len().checked_add(dest_offset_usize) else {
                            reply.error(Errno::EFBIG);
                            return;
                        };
                        if end_offset > attrs.size as usize {
                            attrs.size = end_offset as u64;
                        }
                        if self.killpriv_negotiated {
                            clear_privileges_unprompted(&mut attrs, _req);
                        }
                        self.write_inode(&attrs);

                        reply.written(data.len() as u32);
                    }
                    _ => {
                        reply.error(Errno::EBADF);
                    }
                }
            }
            _ => {
                reply.error(Errno::ENOENT);
            }
        }
    }
}

pub fn check_access(
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    uid: u32,
    gid: u32,
    mut access_mask: AccessFlags,
) -> bool {
    // F_OK tests for existence of file
    if access_mask == AccessFlags::F_OK {
        return true;
    }
    let file_mode = i32::from(file_mode);

    // root is allowed to read & write anything
    if uid == 0 {
        // root only allowed to exec if one of the X bits is set
        // TODO: this code is no-op: `X_OK` is zero.
        access_mask &= AccessFlags::X_OK;
        access_mask &= !AccessFlags::from_bits_retain(access_mask.bits() & (file_mode >> 6));
        access_mask &= !AccessFlags::from_bits_retain(access_mask.bits() & (file_mode >> 3));
        access_mask &= !AccessFlags::from_bits_retain(access_mask.bits() & file_mode);
        return access_mask.is_empty();
    }

    if uid == file_uid {
        access_mask &= !AccessFlags::from_bits_retain(access_mask.bits() & (file_mode >> 6));
    } else if gid == file_gid {
        access_mask &= !AccessFlags::from_bits_retain(access_mask.bits() & (file_mode >> 3));
    } else {
        access_mask &= !AccessFlags::from_bits_retain(access_mask.bits() & file_mode);
    }

    return access_mask.is_empty();
}

fn as_file_kind(mut mode: u32) -> FileKind {
    mode &= libc::S_IFMT as u32;

    if mode == libc::S_IFREG as u32 {
        return FileKind::File;
    } else if mode == libc::S_IFLNK as u32 {
        return FileKind::Symlink;
    } else if mode == libc::S_IFDIR as u32 {
        return FileKind::Directory;
    } else if mode == libc::S_IFCHR as u32 {
        return FileKind::CharDevice;
    } else if mode == libc::S_IFBLK as u32 {
        return FileKind::BlockDevice;
    } else if mode == libc::S_IFIFO as u32 {
        return FileKind::NamedPipe;
    } else if mode == libc::S_IFSOCK as u32 {
        return FileKind::Socket;
    }
    unimplemented!("{mode}");
}

/// Whether the caller holds `CAP_FSETID`, and so keeps suid and sgid on a file it modifies.
///
/// Read from the caller's effective capability set rather than guessed at from its uid, so that
/// a root process which dropped the capability is treated as the unprivileged caller it is.
/// Falls back to the uid where the capability set cannot be read, which is all a request alone
/// would have supported
fn has_fsetid(pid: u32, uid: u32) -> bool {
    // From linux/capability.h; the libc crate does not export the capability numbers
    const CAP_FSETID: u32 = 4;

    if cfg!(target_os = "linux") {
        let path = format!("/proc/{pid}/task/{pid}/status");
        if let Ok(file) = File::open(path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                if let Some(caps) = line.strip_prefix("CapEff:") {
                    if let Ok(caps) = u64::from_str_radix(caps.trim(), 16) {
                        return caps & (1 << CAP_FSETID) != 0;
                    }
                }
            }
        }
    }

    uid == 0
}

fn get_groups(pid: u32) -> Vec<u32> {
    if cfg!(target_os = "linux") {
        let path = format!("/proc/{pid}/task/{pid}/status");
        let file = File::open(path).unwrap();
        for line in BufReader::new(file).lines() {
            let line = line.unwrap();
            if line.starts_with("Groups:") {
                return line["Groups: ".len()..]
                    .split(' ')
                    .filter(|x| !x.trim().is_empty())
                    .map(|x| x.parse::<u32>().unwrap())
                    .collect();
            }
        }
    }

    #[cfg(target_os = "freebsd")]
    {
        // Use libprocstat to query the kernel for the process's groups.
        // Link with: #[link(name = "procstat")]
        use libc::c_int;
        use libc::c_uint;
        use libc::gid_t;

        #[repr(C)]
        struct procstat {
            _priv: [u8; 0],
        }
        #[repr(C)]
        struct kinfo_proc {
            _priv: [u8; 0],
        }

        #[link(name = "procstat")]
        unsafe extern "C" {
            fn procstat_open_sysctl() -> *mut procstat;
            fn procstat_close(ps: *mut procstat);

            fn procstat_getprocs(
                ps: *mut procstat,
                what: c_int,
                arg: c_int,
                count: *mut c_uint,
            ) -> *mut kinfo_proc;
            fn procstat_freeprocs(ps: *mut procstat, kp: *mut kinfo_proc);

            fn procstat_getgroups(
                ps: *mut procstat,
                kp: *mut kinfo_proc,
                count: *mut c_uint,
            ) -> *mut gid_t;
            fn procstat_freegroups(ps: *mut procstat, groups: *mut gid_t);
        }

        // From sys/sysctl.h (KERN_PROC_PID == 1)
        // https://fxr-style headers and manpages document this constant.
        const KERN_PROC_PID: c_int = 1;

        unsafe {
            let ps = procstat_open_sysctl();
            if ps.is_null() {
                return vec![];
            }

            let mut nprocs: c_uint = 0;
            let kps = procstat_getprocs(ps, KERN_PROC_PID, pid as c_int, &mut nprocs);
            if kps.is_null() || nprocs == 0 {
                procstat_close(ps);
                return vec![];
            }

            let mut ngroups: c_uint = 0;
            let groups_ptr = procstat_getgroups(ps, kps, &mut ngroups);

            let mut out = Vec::new();
            if !groups_ptr.is_null() && ngroups > 0 {
                let slice = std::slice::from_raw_parts(groups_ptr, ngroups as usize);
                out.extend(slice.iter().map(|&g| g as u32));
                procstat_freegroups(ps, groups_ptr);
            }

            procstat_freeprocs(ps, kps);
            procstat_close(ps);

            return out;
        }
    }

    #[cfg(not(target_os = "freebsd"))]
    vec![]
}

fn fuse_allow_other_enabled() -> io::Result<bool> {
    let file = File::open("/etc/fuse.conf")?;
    for line in BufReader::new(file).lines() {
        if line?.trim_start().starts_with("user_allow_other") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn main() {
    let args = Args::parse();

    let log_level = match args.v {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    let mut cfg = Config::default();
    cfg.mount_options = vec![MountOption::FSName("fuser".to_string())];

    if args.suid {
        info!("setuid bit support enabled");
        cfg.mount_options.push(MountOption::Suid);
    }
    if args.dev {
        info!("device file support enabled");
        cfg.mount_options.push(MountOption::Dev);
    }
    if args.auto_unmount {
        cfg.mount_options.push(MountOption::AutoUnmount);
    }
    if let Ok(enabled) = fuse_allow_other_enabled() {
        if enabled {
            cfg.acl = SessionACL::All;
        }
    } else {
        eprintln!("Unable to read /etc/fuse.conf");
    }
    if cfg.mount_options.contains(&MountOption::AutoUnmount) && cfg.acl != SessionACL::RootAndOwner
    {
        cfg.acl = SessionACL::All;
    }

    cfg.n_threads = Some(args.n_threads);
    let result = fuser::mount(
        SimpleFS::new(args.data_dir, args.direct_io, args.suid),
        &args.mount_point,
        &cfg,
    );
    if let Err(e) = result {
        // Return a special error code for permission denied, which usually indicates that
        // "user_allow_other" is missing from /etc/fuse.conf
        if e.kind() == ErrorKind::PermissionDenied {
            error!("{e}");
            std::process::exit(2);
        } else {
            error!("{e}");
        }
    }
}
