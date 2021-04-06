#![allow(clippy::needless_return)]

use clap::{crate_version, App, Arg};
use fuser::{consts::FOPEN_DIRECT_IO, serve_sync, DirEntOffset, Errno, INodeNo};
use fuser::{AnyRequest, KernelConfig, MountOption, Response, TimeOrNow, RT as Request};
use fuser::{FileHandle, FilenameInDir, Generation, TimeOrNow::Now};
use log::LevelFilter;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::io::IntoRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{cmp::min, convert::TryInto};
use std::{env, fs, io};

const BLOCK_SIZE: u64 = 512;
const MAX_NAME_LENGTH: u32 = 255;
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;

// Top two file handle bits are used to store permissions
// Note: This isn't safe, since the client can modify those bits. However, this implementation
// is just a toy
const FILE_HANDLE_READ_BIT: u64 = 1 << 63;
const FILE_HANDLE_WRITE_BIT: u64 = 1 << 62;

const FMODE_EXEC: i32 = 0x20;

type DirectoryDescriptor = BTreeMap<PathBuf, (INodeNo, FileKind)>;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
enum FileKind {
    File,
    Directory,
    Symlink,
}

impl From<FileKind> for fuser::FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => fuser::FileType::RegularFile,
            FileKind::Directory => fuser::FileType::Directory,
            FileKind::Symlink => fuser::FileType::Symlink,
        }
    }
}

#[derive(Debug)]
enum XattrNamespace {
    SECURITY,
    SYSTEM,
    TRUSTED,
    USER,
}

fn parse_xattr_namespace(key: &[u8]) -> Result<XattrNamespace, Errno> {
    let user = b"user.";
    if key.len() < user.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..user.len()].eq(user) {
        return Ok(XattrNamespace::USER);
    }

    let system = b"system.";
    if key.len() < system.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..system.len()].eq(system) {
        return Ok(XattrNamespace::SYSTEM);
    }

    let trusted = b"trusted.";
    if key.len() < trusted.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..trusted.len()].eq(trusted) {
        return Ok(XattrNamespace::TRUSTED);
    }

    let security = b"security";
    if key.len() < security.len() {
        return Err(Errno::ENOTSUP);
    }
    if key[..security.len()].eq(security) {
        return Ok(XattrNamespace::SECURITY);
    }

    return Err(Errno::ENOTSUP);
}

fn xattr_access_check(
    key: &[u8],
    access_mask: i32,
    inode_attrs: &InodeAttributes,
    request: &impl Request,
) -> Result<(), Errno> {
    match parse_xattr_namespace(key)? {
        XattrNamespace::SECURITY => {
            if access_mask != libc::R_OK && request.uid() != 0 {
                return Err(Errno::EPERM);
            }
        }
        XattrNamespace::TRUSTED => {
            if request.uid() != 0 {
                return Err(Errno::EPERM);
            }
        }
        XattrNamespace::SYSTEM => {
            if key.eq(b"system.posix_acl_access") {
                check_access(
                    inode_attrs.uid,
                    inode_attrs.gid,
                    inode_attrs.mode,
                    request.uid(),
                    request.gid(),
                    access_mask,
                )
                .map_err(|_| Errno::EPERM)?;
            } else if request.uid() != 0 {
                return Err(Errno::EPERM);
            }
        }
        XattrNamespace::USER => check_access(
            inode_attrs.uid,
            inode_attrs.gid,
            inode_attrs.mode,
            request.uid(),
            request.gid(),
            access_mask,
        )
        .map_err(|_| Errno::EPERM)?,
    }

    Ok(())
}

fn time_now() -> (i64, u32) {
    time_from_system_time(&SystemTime::now())
}

fn system_time_from_time(secs: i64, nsecs: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, nsecs)
    }
}

fn time_from_system_time(system_time: &SystemTime) -> (i64, u32) {
    // Convert to signed 64-bit time with epoch at 0
    match system_time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_nanos()),
        Err(before_epoch_error) => (
            -(before_epoch_error.duration().as_secs() as i64),
            before_epoch_error.duration().subsec_nanos(),
        ),
    }
}

#[derive(Serialize, Deserialize)]
struct InodeAttributes {
    pub inode: INodeNo,
    pub open_file_handles: u64, // Ref count of open file handles to this inode
    pub size: u64,
    pub last_accessed: (i64, u32),
    pub last_modified: (i64, u32),
    pub last_metadata_changed: (i64, u32),
    pub kind: FileKind,
    // Permissions and special mode bits
    pub mode: u16,
    pub hardlinks: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl From<InodeAttributes> for fuser::Attr {
    fn from(x: InodeAttributes) -> Self {
        let a: fuser::FileAttr = x.into();
        a.into()
    }
}
impl From<InodeAttributes> for fuser::FileAttr {
    fn from(attrs: InodeAttributes) -> Self {
        fuser::FileAttr {
            ino: attrs.inode.into(),
            size: attrs.size,
            blocks: (attrs.size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: system_time_from_time(attrs.last_accessed.0, attrs.last_accessed.1),
            mtime: system_time_from_time(attrs.last_modified.0, attrs.last_modified.1),
            ctime: system_time_from_time(
                attrs.last_metadata_changed.0,
                attrs.last_metadata_changed.1,
            ),
            crtime: SystemTime::UNIX_EPOCH,
            kind: attrs.kind.into(),
            perm: attrs.mode,
            nlink: attrs.hardlinks,
            uid: attrs.uid,
            gid: attrs.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            padding: 0,
            flags: 0,
        }
    }
}

// Stores inode metadata data in "$data_dir/inodes" and file contents in "$data_dir/contents"
// Directory data is stored in the file's contents, as a serialized DirectoryDescriptor
struct SimpleFS {
    data_dir: PathBuf,
    next_file_handle: AtomicU64,
    direct_io: bool,
}

impl SimpleFS {
    fn new(data_dir: PathBuf, direct_io: bool) -> SimpleFS {
        fs::create_dir_all(data_dir.join("inodes")).unwrap();
        fs::create_dir_all(data_dir.join("contents")).unwrap();
        let out = SimpleFS {
            data_dir,
            next_file_handle: AtomicU64::new(1),
            direct_io,
        };
        if out.get_inode(INodeNo::ROOT).is_err() {
            // Initialize with empty filesystem
            let root = InodeAttributes {
                inode: INodeNo::ROOT,
                open_file_handles: 0,
                size: 0,
                last_accessed: time_now(),
                last_modified: time_now(),
                last_metadata_changed: time_now(),
                kind: FileKind::Directory,
                mode: 0o777,
                hardlinks: 2,
                uid: 0,
                gid: 0,
                xattrs: Default::default(),
            };
            out.write_inode(&root);
            let mut entries = BTreeMap::new();
            entries.insert(".".into(), (INodeNo::ROOT, FileKind::Directory));
            out.write_directory_content(INodeNo::ROOT, entries);
        };
        out
    }

    fn allocate_next_inode(&self) -> INodeNo {
        let path = Path::new(&self.data_dir).join("superblock");
        let current_inode = if let Ok(file) = File::open(&path) {
            bincode::deserialize_from(file).unwrap()
        } else {
            fuser::FUSE_ROOT_ID
        };

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        bincode::serialize_into(file, &(current_inode + 1)).unwrap();

        INodeNo(current_inode + 1)
    }

    fn allocate_next_file_handle(&self, read: bool, write: bool) -> FileHandle {
        let mut fh = self.next_file_handle.fetch_add(1, Ordering::SeqCst);
        // Assert that we haven't run out of file handles
        assert!(fh < FILE_HANDLE_WRITE_BIT && fh < FILE_HANDLE_READ_BIT);
        if read {
            fh |= FILE_HANDLE_READ_BIT;
        }
        if write {
            fh |= FILE_HANDLE_WRITE_BIT;
        }

        FileHandle(fh)
    }

    fn check_file_handle_read(&self, file_handle: FileHandle) -> Result<(), Errno> {
        if (file_handle.0 & FILE_HANDLE_READ_BIT) != 0 {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }

    fn check_file_handle_write(&self, file_handle: FileHandle) -> Result<(), Errno> {
        if (file_handle.0 & FILE_HANDLE_WRITE_BIT) != 0 {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }

    fn content_path(&self, inode: INodeNo) -> PathBuf {
        Path::new(&self.data_dir)
            .join("contents")
            .join(inode.0.to_string())
    }

    fn get_directory_content(&self, inode: INodeNo) -> Result<DirectoryDescriptor, Errno> {
        let path = Path::new(&self.data_dir)
            .join("contents")
            .join(inode.0.to_string());
        if let Ok(file) = File::open(&path) {
            Ok(bincode::deserialize_from(file).unwrap())
        } else {
            Err(Errno::ENOENT)
        }
    }

    fn write_directory_content(&self, inode: INodeNo, entries: DirectoryDescriptor) {
        let path = Path::new(&self.data_dir)
            .join("contents")
            .join(inode.0.to_string());
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        bincode::serialize_into(file, &entries).unwrap();
    }

    fn get_inode(&self, inode: INodeNo) -> Result<InodeAttributes, Errno> {
        let path = Path::new(&self.data_dir)
            .join("inodes")
            .join(inode.0.to_string());
        if let Ok(file) = File::open(&path) {
            Ok(bincode::deserialize_from(file).unwrap())
        } else {
            Err(Errno::ENOENT)
        }
    }

    fn write_inode(&self, inode: &InodeAttributes) {
        let path = Path::new(&self.data_dir)
            .join("inodes")
            .join(inode.inode.0.to_string());
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        bincode::serialize_into(file, inode).unwrap();
    }

    // Check whether a file should be removed from storage. Should be called after decrementing
    // the link count, or closing a file handle
    fn gc_inode(&self, inode: &InodeAttributes) -> bool {
        if inode.hardlinks == 0 && inode.open_file_handles == 0 {
            let inode_path = Path::new(&self.data_dir)
                .join("inodes")
                .join(inode.inode.0.to_string());
            fs::remove_file(inode_path).unwrap();
            let content_path = Path::new(&self.data_dir)
                .join("contents")
                .join(inode.inode.0.to_string());
            fs::remove_file(content_path).unwrap();

            return true;
        }

        return false;
    }

    fn truncate(
        &self,
        inode: INodeNo,
        new_length: u64,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttributes, Errno> {
        if new_length > MAX_FILE_SIZE {
            return Err(Errno::EFBIG);
        }

        let mut attrs = self.get_inode(inode)?;

        check_access(attrs.uid, attrs.gid, attrs.mode, uid, gid, libc::W_OK)?;

        let path = self.content_path(inode);
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(new_length).unwrap();

        attrs.size = new_length;
        attrs.last_metadata_changed = time_now();
        attrs.last_modified = time_now();

        self.write_inode(&attrs);

        Ok(attrs)
    }

    fn lookup_name(&self, f: FilenameInDir) -> Result<InodeAttributes, Errno> {
        let entries = self.get_directory_content(f.dir)?;
        if let Some((inode, _)) = entries.get(f.name) {
            return self.get_inode(*inode);
        } else {
            return Err(Errno::ENOENT);
        }
    }

    fn insert_link(
        &self,
        req: &impl Request,
        dest: FilenameInDir,
        inode: INodeNo,
        kind: FileKind,
    ) -> Result<(), Errno> {
        if self.lookup_name(dest).is_ok() {
            return Err(Errno::EEXIST);
        }

        let mut parent_attrs = self.get_inode(dest.dir)?;

        check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        )?;
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);

        let mut entries = self.get_directory_content(dest.dir).unwrap();
        entries.insert(dest.name.into(), (inode, kind));
        self.write_directory_content(dest.dir, entries);

        Ok(())
    }

    fn dispatch(&mut self, req: &AnyRequest) -> Result<Response, Errno> {
        use fuser::Operation::*;
        Ok(match req.operation().map_err(|_| Errno::ENOSYS)? {
            Init(x) => x.reply(&KernelConfig::new(x.capabilities(), x.max_readahead())),
            Destroy(x) => x.reply(),
            Lookup(x) => {
                if x.name().as_os_str().len() > MAX_NAME_LENGTH as usize {
                    return Err(Errno::ENAMETOOLONG);
                }
                let parent_attrs = self.get_inode(x.nodeid())?;
                check_access(
                    parent_attrs.uid,
                    parent_attrs.gid,
                    parent_attrs.mode,
                    x.uid(),
                    x.gid(),
                    libc::X_OK,
                )?;

                let attrs = self.lookup_name(x.path())?;
                // TODO: This shouldn't return ino and attr as attr contains ino?
                x.reply(
                    attrs.inode,
                    Generation(0),
                    &attrs.into(),
                    Duration::new(0, 0),
                    Duration::new(0, 0),
                )
            }
            Forget(x) => x.reply(),
            GetAttr(x) => {
                let attrs = self.get_inode(x.nodeid())?;
                x.reply(&Duration::new(0, 0), &attrs.into())
            }
            SetAttr(x) => {
                let mut attrs = self.get_inode(x.nodeid())?;

                if let Some(mode) = x.mode() {
                    debug!("chmod() called with {:?}, {:o}", x.nodeid(), mode);
                    if req.uid() != 0 && req.uid() != attrs.uid {
                        return Err(Errno::EPERM);
                    }
                    attrs.mode = mode as u16;
                    attrs.last_metadata_changed = time_now();
                }

                if x.uid().is_some() || x.gid().is_some() {
                    debug!(
                        "chown() called with {:?} {:?} {:?}",
                        x.nodeid(),
                        x.uid(),
                        x.gid()
                    );
                    if let Some(gid) = x.gid() {
                        // Non-root users can only change gid to a group they're in
                        if req.uid() != 0 && !get_groups(req.pid()).contains(&gid) {
                            return Err(Errno::EPERM);
                        }
                    }
                    if let Some(uid) = x.uid() {
                        if req.uid() != 0
                        // but no-op changes by the owner are not an error
                        && !(uid == attrs.uid && req.uid() == attrs.uid)
                        {
                            return Err(Errno::EPERM);
                        }
                    }
                    // Only owner may change the group
                    if x.gid().is_some() && req.uid() != 0 && req.uid() != attrs.uid {
                        return Err(Errno::EPERM);
                    }

                    if let Some(uid) = x.uid() {
                        attrs.uid = uid;
                    }
                    if let Some(gid) = x.gid() {
                        attrs.gid = gid;
                    }
                    attrs.last_metadata_changed = time_now();
                    self.write_inode(&attrs);
                    return Ok(x.reply(&Duration::new(0, 0), &attrs.into()));
                }

                if let Some(size) = x.size() {
                    debug!("truncate() called with {:?} {:?}", x.nodeid(), size);
                    if let Some(handle) = x.file_handle() {
                        // If the file handle is available, check access locally.
                        // This is important as it preserves the semantic that a file handle opened
                        // with W_OK will never fail to truncate, even if the file has been subsequently
                        // chmod'ed
                        self.check_file_handle_write(handle)?;
                        self.truncate(x.nodeid(), size, 0, 0)?;
                    } else {
                        self.truncate(x.nodeid(), size, req.uid(), req.gid())?;
                    }
                }

                let now = time_now();
                if let Some(atime) = x.atime() {
                    debug!("utimens() called with {:?}, atime={:?}", x.nodeid(), atime);

                    if attrs.uid != req.uid() && req.uid() != 0 && atime != Now {
                        return Err(Errno::EPERM);
                    }

                    if attrs.uid != req.uid() {
                        check_access(
                            attrs.uid,
                            attrs.gid,
                            attrs.mode,
                            req.uid(),
                            req.gid(),
                            libc::W_OK,
                        )?;
                    }

                    attrs.last_accessed = match atime {
                        TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                        Now => now,
                    };
                    attrs.last_metadata_changed = now;
                    self.write_inode(&attrs);
                }
                if let Some(mtime) = x.mtime() {
                    debug!("utimens() called with {:?}, mtime={:?}", x.nodeid(), mtime);

                    if attrs.uid != req.uid() && req.uid() != 0 && mtime != Now {
                        return Err(Errno::EPERM);
                    }

                    if attrs.uid != req.uid() {
                        check_access(
                            attrs.uid,
                            attrs.gid,
                            attrs.mode,
                            req.uid(),
                            req.gid(),
                            libc::W_OK,
                        )?;
                    }

                    attrs.last_modified = match mtime {
                        TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                        Now => now,
                    };
                    attrs.last_metadata_changed = now;
                    self.write_inode(&attrs);
                }

                self.write_inode(&attrs);
                x.reply(&Duration::new(0, 0), &attrs.into())
            }
            ReadLink(x) => {
                debug!("readlink() called on {:?}", x.nodeid());
                let path = self.content_path(x.nodeid());
                let mut file = File::open(&path)?;
                let mut buffer = vec![];
                file.read_to_end(&mut buffer)?;
                x.reply(OsStr::from_bytes(&*buffer).as_ref())
            }
            MkNod(x) => {
                let file_type = x.mode() & libc::S_IFMT as u32;

                if file_type != libc::S_IFREG as u32
                    && file_type != libc::S_IFLNK as u32
                    && file_type != libc::S_IFDIR as u32
                {
                    // TODO
                    warn!("mknod() implementation is incomplete. Only supports regular files, symlinks, and directories. Got {:o}", x.mode());
                    return Err(Errno::ENOSYS);
                }

                if self.lookup_name(x.dest()).is_ok() {
                    return Err(Errno::EEXIST);
                }

                let mut parent_attrs = self.get_inode(x.nodeid())?;

                check_access(
                    parent_attrs.uid,
                    parent_attrs.gid,
                    parent_attrs.mode,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                )?;
                parent_attrs.last_modified = time_now();
                parent_attrs.last_metadata_changed = time_now();
                self.write_inode(&parent_attrs);

                let inode = self.allocate_next_inode();
                let attrs = InodeAttributes {
                    inode,
                    open_file_handles: 0,
                    size: 0,
                    last_accessed: time_now(),
                    last_modified: time_now(),
                    last_metadata_changed: time_now(),
                    kind: as_file_kind(x.mode()),
                    // TODO: suid/sgid not supported
                    mode: (x.mode() & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16,
                    hardlinks: 1,
                    uid: req.uid(),
                    gid: req.gid(),
                    xattrs: Default::default(),
                };
                self.write_inode(&attrs);
                File::create(self.content_path(inode)).unwrap();

                if as_file_kind(x.mode()) == FileKind::Directory {
                    let mut entries = BTreeMap::new();
                    entries.insert(".".into(), (inode, FileKind::Directory));
                    entries.insert("..".into(), (x.nodeid(), FileKind::Directory));
                    self.write_directory_content(inode, entries);
                }

                let mut entries = self.get_directory_content(x.nodeid()).unwrap();
                entries.insert(x.name().into(), (inode, attrs.kind));
                self.write_directory_content(x.nodeid(), entries);

                // TODO: implement flags
                x.reply(
                    inode,
                    Generation(0),
                    &attrs.into(),
                    Duration::new(0, 0),
                    Duration::new(0, 0),
                )
            }
            MkDir(x) => {
                debug!(
                    "mkdir() called with {:?} {:?} {:o}",
                    x.nodeid(),
                    x.name(),
                    x.mode()
                );
                if self.lookup_name(x.dest()).is_ok() {
                    return Err(Errno::EEXIST);
                }

                let mut parent_attrs = self.get_inode(x.nodeid())?;

                check_access(
                    parent_attrs.uid,
                    parent_attrs.gid,
                    parent_attrs.mode,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                )?;
                parent_attrs.last_modified = time_now();
                parent_attrs.last_metadata_changed = time_now();
                self.write_inode(&parent_attrs);

                let inode = self.allocate_next_inode();
                let attrs = InodeAttributes {
                    inode,
                    open_file_handles: 0,
                    size: BLOCK_SIZE,
                    last_accessed: time_now(),
                    last_modified: time_now(),
                    last_metadata_changed: time_now(),
                    kind: FileKind::Directory,
                    // TODO: suid/sgid not supported
                    mode: (x.mode() & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16,
                    hardlinks: 2, // Directories start with link count of 2, since they have a self link
                    uid: req.uid(),
                    gid: req.gid(),
                    xattrs: Default::default(),
                };
                self.write_inode(&attrs);

                let mut entries = BTreeMap::new();
                entries.insert(".".into(), (inode, FileKind::Directory));
                entries.insert("..".into(), (x.nodeid(), FileKind::Directory));
                self.write_directory_content(inode, entries);

                let mut entries = self.get_directory_content(x.nodeid()).unwrap();
                entries.insert(x.name().into(), (inode, FileKind::Directory));
                self.write_directory_content(x.nodeid(), entries);
                x.reply(
                    inode,
                    Generation(0),
                    &attrs.into(),
                    Duration::new(0, 0),
                    Duration::new(0, 0),
                )
            }
            Unlink(x) => {
                debug!("unlink() called with {:?} {:?}", x.nodeid(), x.name());
                let mut attrs = self.lookup_name(x.path())?;
                let mut parent_attrs = self.get_inode(x.nodeid())?;

                check_access(
                    parent_attrs.uid,
                    parent_attrs.gid,
                    parent_attrs.mode,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                )?;

                let uid = req.uid();
                // "Sticky bit" handling
                if parent_attrs.mode & libc::S_ISVTX as u16 != 0
                    && uid != 0
                    && uid != parent_attrs.uid
                    && uid != attrs.uid
                {
                    return Err(Errno::EACCES);
                }

                parent_attrs.last_metadata_changed = time_now();
                parent_attrs.last_modified = time_now();
                self.write_inode(&parent_attrs);

                attrs.hardlinks -= 1;
                attrs.last_metadata_changed = time_now();
                self.write_inode(&attrs);
                self.gc_inode(&attrs);

                let mut entries = self.get_directory_content(x.nodeid()).unwrap();
                entries.remove(x.name());
                self.write_directory_content(x.nodeid(), entries);
                x.reply()
            }
            RmDir(x) => {
                debug!("rmdir() called with {:?} {:?}", x.nodeid(), x.name());
                let mut attrs = self.lookup_name(x.path())?;

                let mut parent_attrs = self.get_inode(x.path().dir)?;

                // Directories always have a self and parent link
                if self.get_directory_content(attrs.inode).unwrap().len() > 2 {
                    return Err(Errno::ENOTEMPTY);
                }
                check_access(
                    parent_attrs.uid,
                    parent_attrs.gid,
                    parent_attrs.mode,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                )?;

                // "Sticky bit" handling
                if parent_attrs.mode & libc::S_ISVTX as u16 != 0
                    && req.uid() != 0
                    && req.uid() != parent_attrs.uid
                    && req.uid() != attrs.uid
                {
                    return Err(Errno::EACCES);
                }

                parent_attrs.last_metadata_changed = time_now();
                parent_attrs.last_modified = time_now();
                self.write_inode(&parent_attrs);

                attrs.hardlinks = 0;
                attrs.last_metadata_changed = time_now();
                self.write_inode(&attrs);
                self.gc_inode(&attrs);

                let mut entries = self.get_directory_content(x.nodeid()).unwrap();
                entries.remove(x.name());
                self.write_directory_content(x.nodeid(), entries);

                x.reply()
            }
            SymLink(x) => {
                debug!(
                    "symlink() called with {:?} {:?} {:?}",
                    x.nodeid(),
                    x.target(),
                    x.link()
                );
                let inode = self.allocate_next_inode();
                let attrs = InodeAttributes {
                    inode,
                    open_file_handles: 0,
                    size: x.link().as_os_str().as_bytes().len() as u64,
                    last_accessed: time_now(),
                    last_modified: time_now(),
                    last_metadata_changed: time_now(),
                    kind: FileKind::Symlink,
                    mode: 0o777,
                    hardlinks: 1,
                    uid: req.uid(),
                    gid: req.gid(),
                    xattrs: Default::default(),
                };

                self.insert_link(&x, x.dest(), inode, FileKind::Symlink)?;
                self.write_inode(&attrs);

                let path = self.content_path(inode);
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&path)
                    .unwrap();
                file.write_all(x.link().as_os_str().as_bytes()).unwrap();
                x.reply(
                    inode,
                    Generation(0),
                    &attrs.into(),
                    Duration::new(0, 0),
                    Duration::new(0, 0),
                )
            }
            Rename(x) => {
                let mut inode_attrs = self.lookup_name(x.src())?;
                let mut parent_attrs = self.get_inode(x.src().dir)?;

                check_access(
                    parent_attrs.uid,
                    parent_attrs.gid,
                    parent_attrs.mode,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                )?;

                // "Sticky bit" handling
                if parent_attrs.mode & libc::S_ISVTX as u16 != 0
                    && req.uid() != 0
                    && req.uid() != parent_attrs.uid
                    && req.uid() != inode_attrs.uid
                {
                    return Err(Errno::EACCES);
                }

                let mut new_parent_attrs = self.get_inode(x.dest().dir)?;

                check_access(
                    new_parent_attrs.uid,
                    new_parent_attrs.gid,
                    new_parent_attrs.mode,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                )?;

                // "Sticky bit" handling in new_parent
                if new_parent_attrs.mode & libc::S_ISVTX as u16 != 0 {
                    if let Ok(existing_attrs) = self.lookup_name(x.dest()) {
                        if req.uid() != 0
                            && req.uid() != new_parent_attrs.uid
                            && req.uid() != existing_attrs.uid
                        {
                            return Err(Errno::EACCES);
                        }
                    }
                }

                // Only overwrite an existing directory if it's empty
                if let Ok(new_name_attrs) = self.lookup_name(x.dest()) {
                    if new_name_attrs.kind == FileKind::Directory
                        && self
                            .get_directory_content(new_name_attrs.inode)
                            .unwrap()
                            .len()
                            > 2
                    {
                        return Err(Errno::ENOTEMPTY);
                    }
                }

                // Only move an existing directory to a new parent, if we have write access to it,
                // because that will change the ".." link in it
                if inode_attrs.kind == FileKind::Directory && x.src().dir != x.dest().dir {
                    check_access(
                        inode_attrs.uid,
                        inode_attrs.gid,
                        inode_attrs.mode,
                        req.uid(),
                        req.gid(),
                        libc::W_OK,
                    )?;
                }

                // If target already exists decrement its hardlink count
                if let Ok(mut existing_inode_attrs) = self.lookup_name(x.dest()) {
                    let mut entries = self.get_directory_content(x.dest().dir).unwrap();
                    entries.remove(x.dest().name);
                    self.write_directory_content(x.dest().dir, entries);

                    if existing_inode_attrs.kind == FileKind::Directory {
                        existing_inode_attrs.hardlinks = 0;
                    } else {
                        existing_inode_attrs.hardlinks -= 1;
                    }
                    existing_inode_attrs.last_metadata_changed = time_now();
                    self.write_inode(&existing_inode_attrs);
                    self.gc_inode(&existing_inode_attrs);
                }

                let mut entries = self.get_directory_content(x.src().dir).unwrap();
                entries.remove(x.src().name);
                self.write_directory_content(x.src().dir, entries);

                let mut entries = self.get_directory_content(x.dest().dir).unwrap();
                entries.insert(x.dest().name.into(), (inode_attrs.inode, inode_attrs.kind));
                self.write_directory_content(x.dest().dir, entries);

                parent_attrs.last_metadata_changed = time_now();
                parent_attrs.last_modified = time_now();
                self.write_inode(&parent_attrs);
                new_parent_attrs.last_metadata_changed = time_now();
                new_parent_attrs.last_modified = time_now();
                self.write_inode(&new_parent_attrs);
                inode_attrs.last_metadata_changed = time_now();
                self.write_inode(&inode_attrs);

                if inode_attrs.kind == FileKind::Directory {
                    let mut entries = self.get_directory_content(inode_attrs.inode).unwrap();
                    entries.insert("..".into(), (x.dest().dir, FileKind::Directory));
                    self.write_directory_content(inode_attrs.inode, entries);
                }

                x.reply()
            }
            Link(x) => {
                debug!("link() called for {:?}, {:?}", x.inode_no(), x.dest());
                let mut attrs = self.get_inode(x.nodeid())?;
                self.insert_link(&x, x.dest(), x.inode_no(), attrs.kind)?;
                attrs.hardlinks += 1;
                attrs.last_metadata_changed = time_now();
                self.write_inode(&attrs);
                x.reply(
                    x.inode_no(),
                    Generation(0),
                    &attrs.into(),
                    Duration::new(0, 0),
                    Duration::new(0, 0),
                )
            }
            Open(x) => {
                debug!("open() called for {:?}", x.nodeid());
                // TODO: Make a helper to handle these fininiky behaviours
                // TODO: Rename flags to flags_u32 and add another strongly typed flags
                let (access_mask, read, write) = match x.flags() & libc::O_ACCMODE {
                    libc::O_RDONLY => {
                        // Behavior is undefined, but most filesystems return EACCES
                        if x.flags() & libc::O_TRUNC != 0 {
                            return Err(Errno::EACCES);
                        }
                        if x.flags() & FMODE_EXEC != 0 {
                            // Open is from internal exec syscall
                            (libc::X_OK, true, false)
                        } else {
                            (libc::R_OK, true, false)
                        }
                    }
                    libc::O_WRONLY => (libc::W_OK, false, true),
                    libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
                    // Exactly one access mode flag must be specified
                    _ => {
                        return Err(Errno::EINVAL);
                    }
                };

                let mut attr = self.get_inode(x.nodeid())?;
                check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    req.uid(),
                    req.gid(),
                    access_mask,
                )?;
                attr.open_file_handles += 1;
                self.write_inode(&attr);
                let open_flags = if self.direct_io { FOPEN_DIRECT_IO } else { 0 };
                x.reply(self.allocate_next_file_handle(read, write), open_flags)
            }
            Read(x) => {
                debug!(
                    "read() called on {:?} offset={:?} size={:?}",
                    x.nodeid(),
                    x.offset(),
                    x.size()
                );
                assert!(x.offset() >= 0);
                self.check_file_handle_read(x.file_handle())?;

                let path = self.content_path(x.nodeid());
                let file = File::open(&path).map_err(|_| Errno::ENOENT)?;
                let file_size = file.metadata().unwrap().len();
                // Could underflow if file length is less than local_start
                let read_size = min(x.size(), file_size.saturating_sub(x.offset() as u64) as u32);

                let mut buffer = vec![0; read_size as usize];
                file.read_exact_at(&mut buffer, x.offset() as u64).unwrap();
                x.reply(buffer)
            }
            Write(x) => {
                debug!(
                    "write() called with {:?} size={:?}",
                    x.nodeid(),
                    x.data().len()
                );
                assert!(x.offset() >= 0);
                self.check_file_handle_write(x.file_handle())?;

                let path = self.content_path(x.nodeid());
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(|_| Errno::EBADF)?;
                file.seek(SeekFrom::Start(x.offset() as u64)).unwrap();
                file.write_all(x.data()).unwrap();

                let mut attrs = self.get_inode(x.nodeid()).unwrap();
                attrs.last_metadata_changed = time_now();
                attrs.last_modified = time_now();
                if x.data().len() + x.offset() as usize > attrs.size as usize {
                    attrs.size = (x.data().len() + x.offset() as usize) as u64;
                }
                self.write_inode(&attrs);

                x.reply(x.data().len().try_into().expect("Too big"))
            }
            Release(x) => {
                if let Ok(mut attrs) = self.get_inode(x.nodeid()) {
                    attrs.open_file_handles -= 1;
                }
                x.reply()
            }
            OpenDir(x) => {
                debug!("opendir() called on {:?}", x.nodeid());
                let (access_mask, read, write) = match x.flags() & libc::O_ACCMODE {
                    libc::O_RDONLY => {
                        // Behavior is undefined, but most filesystems return EACCES
                        if x.flags() & libc::O_TRUNC != 0 {
                            return Err(Errno::EACCES);
                        }
                        (libc::R_OK, true, false)
                    }
                    libc::O_WRONLY => (libc::W_OK, false, true),
                    libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
                    // Exactly one access mode flag must be specified
                    _ => {
                        return Err(Errno::EINVAL);
                    }
                };

                let mut attr = self.get_inode(x.nodeid())?;
                check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    req.uid(),
                    req.gid(),
                    access_mask,
                )?;
                attr.open_file_handles += 1;
                self.write_inode(&attr);
                let open_flags = if self.direct_io { FOPEN_DIRECT_IO } else { 0 };
                x.reply(self.allocate_next_file_handle(read, write), open_flags)
            }
            ReadDir(x) => {
                debug!("readdir() called with {:?}", x.nodeid());
                assert!(x.offset() >= 0);
                let entries = self.get_directory_content(x.nodeid())?;
                x.reply(
                    &mut entries
                        .iter()
                        .skip(x.offset() as usize)
                        .enumerate()
                        .map(|(n, (name, (inode, filekind)))| {
                            fuser::DirEntry::new(
                                *inode,
                                DirEntOffset(x.offset() + n as i64 + 1),
                                (*filekind).into(),
                                name,
                            )
                        })
                        .peekable(),
                )
            }
            ReleaseDir(x) => {
                if let Ok(mut attrs) = self.get_inode(x.nodeid()) {
                    attrs.open_file_handles -= 1;
                }
                x.reply()
            }
            StatFs(x) => {
                warn!("statfs() implementation is a stub");
                // TODO: real implementation of this
                x.reply(
                    10,
                    10,
                    10,
                    1,
                    10,
                    BLOCK_SIZE as u32,
                    MAX_NAME_LENGTH,
                    BLOCK_SIZE as u32,
                )
            }
            SetXAttr(x) => {
                let mut attrs = self.get_inode(x.nodeid()).map_err(|_| Errno::EBADF)?;
                xattr_access_check(x.name().as_bytes(), libc::W_OK, &attrs, req)?;

                attrs
                    .xattrs
                    .insert(x.name().as_bytes().to_vec(), x.value().to_vec());
                attrs.last_metadata_changed = time_now();
                self.write_inode(&attrs);
                x.reply()
            }
            GetXAttr(x) => {
                let attrs = self.get_inode(x.nodeid()).map_err(|_| Errno::EBADF)?;
                xattr_access_check(x.name().as_bytes(), libc::R_OK, &attrs, req)?;

                let data = attrs
                    .xattrs
                    .get(x.name().as_bytes())
                    .ok_or(Errno::NO_XATTR)?;
                x.reply(data)
            }
            ListXAttr(x) => {
                let attrs = self.get_inode(x.nodeid()).map_err(|_| Errno::EBADF)?;
                // Convert to concatenated null-terminated strings
                x.reply(attrs.xattrs.keys().map(|x| OsStr::from_bytes(x)))
            }
            RemoveXAttr(x) => {
                let mut attrs = self.get_inode(x.nodeid()).map_err(|_| Errno::EBADF)?;
                xattr_access_check(x.name().as_bytes(), libc::W_OK, &attrs, req)?;

                attrs
                    .xattrs
                    .remove(x.name().as_bytes())
                    .ok_or(Errno::NO_XATTR)?;
                attrs.last_metadata_changed = time_now();
                self.write_inode(&attrs);
                x.reply()
            }
            Access(x) => {
                debug!("access() called with {:?} {:?}", x.nodeid(), x.mask());
                let attr = self.get_inode(x.nodeid())?;
                check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    req.uid(),
                    req.gid(),
                    x.mask(),
                )?;
                x.reply()
            }
            Create(x) => {
                debug!("create() called with {:?}", x.dest());
                if self.lookup_name(x.dest()).is_ok() {
                    return Err(Errno::EEXIST);
                }

                let (read, write) = match x.flags() & libc::O_ACCMODE {
                    libc::O_RDONLY => (true, false),
                    libc::O_WRONLY => (false, true),
                    libc::O_RDWR => (true, true),
                    // Exactly one access mode flag must be specified
                    _ => {
                        return Err(Errno::EINVAL);
                    }
                };

                let mut parent_attrs = self.get_inode(x.dest().dir)?;

                check_access(
                    parent_attrs.uid,
                    parent_attrs.gid,
                    parent_attrs.mode,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                )?;
                parent_attrs.last_modified = time_now();
                parent_attrs.last_metadata_changed = time_now();
                self.write_inode(&parent_attrs);

                let inode = self.allocate_next_inode();
                let attrs = InodeAttributes {
                    inode,
                    open_file_handles: 0,
                    size: 0,
                    last_accessed: time_now(),
                    last_modified: time_now(),
                    last_metadata_changed: time_now(),
                    kind: as_file_kind(x.mode()),
                    // TODO: suid/sgid not supported
                    mode: (x.mode() & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16,
                    hardlinks: 1,
                    uid: req.uid(),
                    gid: req.gid(),
                    xattrs: Default::default(),
                };
                self.write_inode(&attrs);
                File::create(self.content_path(inode)).unwrap();

                if as_file_kind(x.mode()) == FileKind::Directory {
                    let mut entries = BTreeMap::new();
                    entries.insert(".".into(), (inode, FileKind::Directory));
                    entries.insert("..".into(), (x.dest().dir, FileKind::Directory));
                    self.write_directory_content(inode, entries);
                }

                let mut entries = self.get_directory_content(x.dest().dir).unwrap();
                entries.insert(x.dest().name.into(), (inode, attrs.kind));
                self.write_directory_content(x.dest().dir, entries);

                // TODO: implement flags
                x.reply(
                    &Duration::new(0, 0),
                    &attrs.into(),
                    Generation(0),
                    self.allocate_next_file_handle(read, write),
                    0,
                )
            }

            #[cfg(feature = "abi-7-19")]
            #[cfg(target_os = "linux")]
            FAllocate(x) => {
                let path = self.content_path(x.nodeid());
                let file = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(|_| Errno::ENOENT)?;
                unsafe {
                    libc::fallocate64(file.into_raw_fd(), x.mode_i32(), x.offset(), x.len());
                }
                // TODO: Make mode -> mode_u32
                if x.mode_i32() & libc::FALLOC_FL_KEEP_SIZE == 0 {
                    let mut attrs = self.get_inode(x.nodeid()).unwrap();
                    attrs.last_metadata_changed = time_now();
                    attrs.last_modified = time_now();
                    let end = x.range()?.end;
                    if end > attrs.size {
                        attrs.size = end;
                    }
                    self.write_inode(&attrs);
                }
                x.reply()
            }
            #[cfg(feature = "abi-7-28")]
            CopyFileRange(x) => {
                debug!(
                    "copy_file_range() called with src ({:?}) dest ({:?}) size={}",
                    x.src(),
                    x.dest(),
                    x.len()
                );
                self.check_file_handle_read(x.src().file_handle)?;
                self.check_file_handle_write(x.dest().file_handle)?;

                let src_path = self.content_path(x.src().inode);
                let file = File::open(&src_path).map_err(|_| Errno::ENOENT)?;
                let file_size = file.metadata().unwrap().len();
                // Could underflow if file length is less than local_start
                let read_size = min(x.len(), file_size.saturating_sub(x.src().offset as u64));

                let mut data = vec![0; read_size as usize];
                file.read_exact_at(&mut data, x.src().offset as u64)
                    .unwrap();

                let dest_path = self.content_path(x.dest().inode);
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&dest_path)
                    .map_err(|_| Errno::EBADF)?;
                file.seek(SeekFrom::Start(x.dest().offset as u64)).unwrap();
                file.write_all(&data).unwrap();

                let mut attrs = self.get_inode(x.dest().inode).unwrap();
                attrs.last_metadata_changed = time_now();
                attrs.last_modified = time_now();
                if data.len() + x.dest().offset as usize > attrs.size as usize {
                    attrs.size = (data.len() + x.dest().offset as usize) as u64;
                }
                self.write_inode(&attrs);

                x.reply(data.len() as u32)
            }
            _ => return Err(Errno::ENOSYS),
        })
    }
}

fn check_access(
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    uid: u32,
    gid: u32,
    mut access_mask: i32,
) -> Result<(), Errno> {
    // F_OK tests for existence of file
    if access_mask == libc::F_OK {
        return Ok(());
    }
    let file_mode = i32::from(file_mode);

    // root is allowed to read & write anything
    if uid == 0 {
        // root only allowed to exec if one of the X bits is set
        access_mask &= libc::X_OK;
        access_mask -= access_mask & (file_mode >> 6);
        access_mask -= access_mask & (file_mode >> 3);
        access_mask -= access_mask & file_mode;
    } else {
        if uid == file_uid {
            access_mask -= access_mask & (file_mode >> 6);
        } else if gid == file_gid {
            access_mask -= access_mask & (file_mode >> 3);
        } else {
            access_mask -= access_mask & file_mode;
        }
    }

    if access_mask == 0 {
        Ok(())
    } else {
        Err(Errno::EACCES)
    }
}

fn as_file_kind(mut mode: u32) -> FileKind {
    mode &= libc::S_IFMT as u32;

    if mode == libc::S_IFREG as u32 {
        return FileKind::File;
    } else if mode == libc::S_IFLNK as u32 {
        return FileKind::Symlink;
    } else if mode == libc::S_IFDIR as u32 {
        return FileKind::Directory;
    } else {
        unimplemented!("{}", mode);
    }
}

fn get_groups(pid: u32) -> Vec<u32> {
    let path = format!("/proc/{}/task/{}/status", pid, pid);
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
    let matches = App::new("Fuser")
        .version(crate_version!())
        .author("Christopher Berner")
        .arg(
            Arg::with_name("data-dir")
                .long("data-dir")
                .value_name("DIR")
                .default_value("/tmp/fuser")
                .help("Set local directory used to store data")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mount-point")
                .long("mount-point")
                .value_name("MOUNT_POINT")
                .default_value("")
                .help("Act as a client, and mount FUSE at given path")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("direct-io")
                .long("direct-io")
                .requires("mount-point")
                .help("Mount FUSE with direct IO"),
        )
        .arg(
            Arg::with_name("fsck")
                .long("fsck")
                .help("Run a filesystem check"),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let verbosity: u64 = matches.occurrences_of("v");
    let log_level = match verbosity {
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

    let mut options = vec![
        MountOption::FSName("fuser".to_string()),
        MountOption::AutoUnmount,
    ];
    if let Ok(enabled) = fuse_allow_other_enabled() {
        if enabled {
            options.push(MountOption::AllowOther);
        }
    } else {
        eprintln!("Unable to read /etc/fuse.conf");
    }

    let data_dir = matches.value_of("data-dir").unwrap_or_default().into();

    let mountpoint: String = matches
        .value_of("mount-point")
        .unwrap_or_default()
        .to_string();

    let (chan, _mount) = fuser::mount3(mountpoint.as_ref(), &options).unwrap();

    let mut fs = SimpleFS::new(data_dir, matches.is_present("direct-io"));
    serve_sync(&chan, |req| fs.dispatch(req)).unwrap()
}
