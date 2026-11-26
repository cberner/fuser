//! The client side of an in-process FUSE connection: what a kernel would do.
//!
//! Each call builds the request a kernel would send, queues it on the [`Transport`], waits
//! for the reply with the same `unique` and decodes it. The session at the other end
//! dispatches the request to the filesystem as it would one from `/dev/fuse`.
//!
//! SMB names files by path, so paths are resolved to inodes by LOOKUP from the root, and the
//! directories on the way are cached. Only this client changes the namespace, and it drops
//! what a rename or removal makes stale; a cached directory the filesystem removed by itself
//! is noticed when a lookup under it fails, and the path is then resolved again.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::SystemTime;

use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

use super::transport::Transport;
use crate::Errno;
use crate::FileAttr;
use crate::FileType;
use crate::INodeNo;
use crate::ll::flags::fattr_flags::FattrFlags;
use crate::ll::flags::getattr_flags::GetattrFlags;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi::FUSE_KERNEL_MINOR_VERSION;
use crate::ll::fuse_abi::FUSE_KERNEL_VERSION;
use crate::ll::fuse_abi::fuse_attr;
use crate::ll::fuse_abi::fuse_attr_out;
use crate::ll::fuse_abi::fuse_create_in;
use crate::ll::fuse_abi::fuse_dirent;
use crate::ll::fuse_abi::fuse_entry_out;
use crate::ll::fuse_abi::fuse_flush_in;
use crate::ll::fuse_abi::fuse_fsync_in;
use crate::ll::fuse_abi::fuse_getattr_in;
use crate::ll::fuse_abi::fuse_in_header;
use crate::ll::fuse_abi::fuse_init_in;
use crate::ll::fuse_abi::fuse_init_out;
use crate::ll::fuse_abi::fuse_kstatfs;
use crate::ll::fuse_abi::fuse_mkdir_in;
use crate::ll::fuse_abi::fuse_opcode;
use crate::ll::fuse_abi::fuse_open_in;
use crate::ll::fuse_abi::fuse_open_out;
use crate::ll::fuse_abi::fuse_out_header;
use crate::ll::fuse_abi::fuse_read_in;
use crate::ll::fuse_abi::fuse_release_in;
use crate::ll::fuse_abi::fuse_rename_in;
use crate::ll::fuse_abi::fuse_setattr_in;
use crate::ll::fuse_abi::fuse_statfs_out;
use crate::ll::fuse_abi::fuse_write_in;
use crate::ll::fuse_abi::fuse_write_out;
use crate::time::system_time_from_time;
use crate::time::time_from_system_time;

/// Readahead offered in INIT. Nothing reads ahead here; filesystems may size buffers by it
const MAX_READAHEAD: u32 = 1024 * 1024;
/// Writes are split into requests of at most this, until INIT has negotiated `max_write`
const DEFAULT_MAX_WRITE: u32 = 4096;

/// A file or directory the filesystem has looked up: its node id and attributes
#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub(crate) id: INodeNo,
    pub(crate) attr: FileAttr,
}

/// One entry of a READDIR reply
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirEntry {
    pub(crate) ino: u64,
    pub(crate) offset: u64,
    pub(crate) name: OsString,
}

/// What a SETATTR changes
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SetAttr {
    pub(crate) size: Option<u64>,
    pub(crate) mode: Option<u32>,
    pub(crate) atime: Option<SystemTime>,
    pub(crate) mtime: Option<SystemTime>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) crtime: Option<SystemTime>,
}

/// The volume statistics of a STATFS reply
#[derive(Debug, Clone, Copy)]
pub(crate) struct StatFs {
    pub(crate) blocks: u64,
    pub(crate) bfree: u64,
    pub(crate) bavail: u64,
    pub(crate) bsize: u32,
    pub(crate) namelen: u32,
    pub(crate) frsize: u32,
}

/// Where a path could not be resolved
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathError {
    /// A directory on the way to the last component
    Parent(Errno),
    /// The last component
    Last(Errno),
}

/// An INIT request that has been queued, and whose reply is still to come
#[derive(Debug)]
pub(crate) struct PendingInit(mpsc::Receiver<Vec<u8>>);

/// Makes FUSE requests over an in-process [`Transport`]
#[derive(Debug)]
pub(crate) struct Client {
    transport: Arc<Transport>,
    unique: AtomicU64,
    uid: u32,
    gid: u32,
    max_write: AtomicU32,
    /// The filesystem answered ENOSYS to these, so they are not sent again, as the kernel does
    no_flush: AtomicBool,
    no_fsync: AtomicBool,
    /// Directories looked up so far, by their path from the root
    dirs: Mutex<HashMap<Vec<String>, INodeNo>>,
}

impl Client {
    /// Requests carry `uid` and `gid` as their caller: the requests come from SMB clients,
    /// which do not say which local user made them
    pub(crate) fn new(transport: Arc<Transport>, uid: u32, gid: u32) -> Self {
        Client {
            transport,
            unique: AtomicU64::new(1),
            uid,
            gid,
            max_write: AtomicU32::new(DEFAULT_MAX_WRITE),
            no_flush: AtomicBool::new(false),
            no_fsync: AtomicBool::new(false),
            dirs: Mutex::new(HashMap::new()),
        }
    }

    /// Queue INIT. It must be the first request; its reply comes once the session reads it.
    pub(crate) fn begin_init(&self) -> Result<PendingInit, Errno> {
        let arg = fuse_init_in {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: MAX_READAHEAD,
            // Nothing that needs support from this side, which serves requests one at a time
            // and does not cache
            flags: (InitFlags::FUSE_ASYNC_READ | InitFlags::FUSE_BIG_WRITES).bits() as u32,
            flags2: 0,
            unused: [0; 11],
        };
        // ABI 7.36 extended fuse_init_in, and older peers send the first four fields only
        let size = if FUSE_KERNEL_MINOR_VERSION >= 36 {
            size_of::<fuse_init_in>()
        } else {
            std::mem::offset_of!(fuse_init_in, flags2)
        };
        let (unique, request) = self.encode(
            fuse_opcode::FUSE_INIT,
            INodeNo(0),
            &[&arg.as_bytes()[..size]],
        );
        Ok(PendingInit(self.transport.request(unique, request)?))
    }

    /// Wait for the reply to INIT, and take the `max_write` it negotiated
    pub(crate) fn complete_init(&self, pending: PendingInit) -> Result<(), Errno> {
        let payload = decode_reply(pending.0.recv().map_err(|_| Errno::ENOTCONN)?)?;
        // The reply is cut short for older minors: read what there is
        let mut init = fuse_init_out::new_zeroed();
        let size = payload.len().min(size_of::<fuse_init_out>());
        init.as_mut_bytes()[..size].copy_from_slice(&payload[..size]);
        if init.major != FUSE_KERNEL_VERSION {
            return Err(Errno::EPROTO);
        }
        if init.max_write > 0 {
            self.max_write.store(init.max_write, Ordering::Relaxed);
        }
        Ok(())
    }

    fn encode(&self, opcode: fuse_opcode, nodeid: INodeNo, args: &[&[u8]]) -> (u64, Vec<u8>) {
        let unique = self.unique.fetch_add(1, Ordering::Relaxed);
        let len = size_of::<fuse_in_header>() + args.iter().map(|arg| arg.len()).sum::<usize>();
        let header = fuse_in_header {
            len: len as u32,
            opcode: opcode as u32,
            unique,
            nodeid: nodeid.0,
            uid: self.uid,
            gid: self.gid,
            pid: 0,
            padding: 0,
        };
        let mut request = Vec::with_capacity(len);
        request.extend_from_slice(header.as_bytes());
        for arg in args {
            request.extend_from_slice(arg);
        }
        (unique, request)
    }

    /// Make one request and return the payload of its reply, after `fuse_out_header`
    fn call(&self, opcode: fuse_opcode, nodeid: INodeNo, args: &[&[u8]]) -> Result<Vec<u8>, Errno> {
        let (unique, request) = self.encode(opcode, nodeid, args);
        let reply = self.transport.request(unique, request)?;
        decode_reply(reply.recv().map_err(|_| Errno::ENOTCONN)?)
    }

    pub(crate) fn lookup(&self, parent: INodeNo, name: &str) -> Result<Node, Errno> {
        let name = c_name(name)?;
        let reply = self.call(fuse_opcode::FUSE_LOOKUP, parent, &[&name])?;
        node(&reply)
    }

    pub(crate) fn getattr(&self, node: INodeNo, fh: Option<u64>) -> Result<FileAttr, Errno> {
        let arg = fuse_getattr_in {
            getattr_flags: if fh.is_some() {
                GetattrFlags::FUSE_GETATTR_FH.bits()
            } else {
                0
            },
            dummy: 0,
            fh: fh.unwrap_or(0),
        };
        let reply = self.call(fuse_opcode::FUSE_GETATTR, node, &[arg.as_bytes()])?;
        attr_out(&reply)
    }

    pub(crate) fn setattr(
        &self,
        node: INodeNo,
        fh: Option<u64>,
        changes: &SetAttr,
    ) -> Result<FileAttr, Errno> {
        let mut arg = fuse_setattr_in::new_zeroed();
        let mut valid = FattrFlags::empty();
        if let Some(fh) = fh {
            valid |= FattrFlags::FATTR_FH;
            arg.fh = fh;
        }
        if let Some(size) = changes.size {
            valid |= FattrFlags::FATTR_SIZE;
            arg.size = size;
        }
        if let Some(mode) = changes.mode {
            valid |= FattrFlags::FATTR_MODE;
            arg.mode = mode;
        }
        if let Some(atime) = changes.atime {
            valid |= FattrFlags::FATTR_ATIME;
            (arg.atime, arg.atimensec) = time_from_system_time(&atime);
        }
        if let Some(mtime) = changes.mtime {
            valid |= FattrFlags::FATTR_MTIME;
            (arg.mtime, arg.mtimensec) = time_from_system_time(&mtime);
        }
        #[cfg(target_os = "macos")]
        if let Some(crtime) = changes.crtime {
            valid |= FattrFlags::FATTR_CRTIME;
            let (secs, nsecs) = time_from_system_time(&crtime);
            arg.crtime = secs as u64;
            arg.crtimensec = nsecs;
        }
        arg.valid = valid.bits();
        let reply = self.call(fuse_opcode::FUSE_SETATTR, node, &[arg.as_bytes()])?;
        attr_out(&reply)
    }

    fn open_common(&self, opcode: fuse_opcode, node: INodeNo, flags: i32) -> Result<u64, Errno> {
        let arg = fuse_open_in {
            flags,
            open_flags: 0,
        };
        let reply = self.call(opcode, node, &[arg.as_bytes()])?;
        let (open, _) = fuse_open_out::read_from_prefix(&reply).map_err(|_| Errno::EIO)?;
        Ok(open.fh)
    }

    pub(crate) fn open(&self, node: INodeNo, flags: i32) -> Result<u64, Errno> {
        self.open_common(fuse_opcode::FUSE_OPEN, node, flags)
    }

    pub(crate) fn opendir(&self, node: INodeNo) -> Result<u64, Errno> {
        self.open_common(fuse_opcode::FUSE_OPENDIR, node, libc::O_RDONLY)
    }

    /// Create and open the regular file `name`
    pub(crate) fn create(
        &self,
        parent: INodeNo,
        name: &str,
        mode: u32,
        flags: i32,
    ) -> Result<(Node, u64), Errno> {
        let name = c_name(name)?;
        // mode_t is u16 on macOS
        #[allow(clippy::unnecessary_cast)]
        let regular = libc::S_IFREG as u32;
        let arg = fuse_create_in {
            flags: flags | libc::O_CREAT | libc::O_EXCL,
            mode: mode | regular,
            umask: 0,
            open_flags: 0,
        };
        let reply = self.call(fuse_opcode::FUSE_CREATE, parent, &[arg.as_bytes(), &name])?;
        let created = node(&reply)?;
        let open = reply
            .get(size_of::<fuse_entry_out>()..)
            .and_then(|rest| fuse_open_out::read_from_prefix(rest).ok())
            .ok_or(Errno::EIO)?
            .0;
        Ok((created, open.fh))
    }

    pub(crate) fn mkdir(&self, parent: INodeNo, name: &str, mode: u32) -> Result<Node, Errno> {
        let name = c_name(name)?;
        let arg = fuse_mkdir_in { mode, umask: 0 };
        let reply = self.call(fuse_opcode::FUSE_MKDIR, parent, &[arg.as_bytes(), &name])?;
        node(&reply)
    }

    pub(crate) fn read(
        &self,
        node: INodeNo,
        fh: u64,
        offset: u64,
        size: u32,
        flags: i32,
    ) -> Result<Vec<u8>, Errno> {
        let arg = fuse_read_in {
            fh,
            offset,
            size,
            read_flags: 0,
            lock_owner: 0,
            flags,
            padding: 0,
        };
        self.call(fuse_opcode::FUSE_READ, node, &[arg.as_bytes()])
    }

    /// Write all of `data`, in requests of at most the negotiated `max_write`. Returns how much
    /// was written, which falls short only if the filesystem wrote less than it was given.
    pub(crate) fn write(
        &self,
        node: INodeNo,
        fh: u64,
        offset: u64,
        data: &[u8],
        flags: i32,
    ) -> Result<u32, Errno> {
        let max_write = self.max_write.load(Ordering::Relaxed).max(1) as usize;
        let mut written = 0usize;
        for chunk in data.chunks(max_write) {
            let arg = fuse_write_in {
                fh,
                offset: (offset + written as u64) as i64,
                size: chunk.len() as u32,
                write_flags: 0,
                lock_owner: 0,
                flags,
                padding: 0,
            };
            let reply = self.call(fuse_opcode::FUSE_WRITE, node, &[arg.as_bytes(), chunk])?;
            let (out, _) = fuse_write_out::read_from_prefix(&reply).map_err(|_| Errno::EIO)?;
            written += out.size as usize;
            if (out.size as usize) < chunk.len() {
                break;
            }
        }
        Ok(written as u32)
    }

    /// Make a request that a filesystem may leave unimplemented, which then succeeds
    fn call_optional(
        &self,
        unimplemented: &AtomicBool,
        opcode: fuse_opcode,
        node: INodeNo,
        arg: &[u8],
    ) -> Result<(), Errno> {
        if unimplemented.load(Ordering::Relaxed) {
            return Ok(());
        }
        match self.call(opcode, node, &[arg]) {
            Err(Errno::ENOSYS) => {
                unimplemented.store(true, Ordering::Relaxed);
                Ok(())
            }
            result => result.map(drop),
        }
    }

    pub(crate) fn flush(&self, node: INodeNo, fh: u64) -> Result<(), Errno> {
        let arg = fuse_flush_in {
            fh,
            unused: 0,
            padding: 0,
            lock_owner: 0,
        };
        self.call_optional(
            &self.no_flush,
            fuse_opcode::FUSE_FLUSH,
            node,
            arg.as_bytes(),
        )
    }

    pub(crate) fn fsync(&self, node: INodeNo, fh: u64) -> Result<(), Errno> {
        let arg = fuse_fsync_in {
            fh,
            fsync_flags: 0,
            padding: 0,
        };
        self.call_optional(
            &self.no_fsync,
            fuse_opcode::FUSE_FSYNC,
            node,
            arg.as_bytes(),
        )
    }

    fn release_common(
        &self,
        opcode: fuse_opcode,
        node: INodeNo,
        fh: u64,
        flags: i32,
    ) -> Result<(), Errno> {
        let arg = fuse_release_in {
            fh,
            flags,
            release_flags: 0,
            lock_owner: 0,
        };
        self.call(opcode, node, &[arg.as_bytes()]).map(drop)
    }

    pub(crate) fn release(&self, node: INodeNo, fh: u64, flags: i32) -> Result<(), Errno> {
        self.release_common(fuse_opcode::FUSE_RELEASE, node, fh, flags)
    }

    pub(crate) fn releasedir(&self, node: INodeNo, fh: u64) -> Result<(), Errno> {
        self.release_common(fuse_opcode::FUSE_RELEASEDIR, node, fh, libc::O_RDONLY)
    }

    /// Read entries of the open directory `fh` from `offset`, at most `size` bytes of them. An
    /// empty list is the end of the directory.
    pub(crate) fn readdir(
        &self,
        node: INodeNo,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<DirEntry>, Errno> {
        let arg = fuse_read_in {
            fh,
            offset,
            size,
            read_flags: 0,
            lock_owner: 0,
            flags: libc::O_RDONLY,
            padding: 0,
        };
        let reply = self.call(fuse_opcode::FUSE_READDIR, node, &[arg.as_bytes()])?;
        Ok(dir_entries(&reply))
    }

    pub(crate) fn unlink(&self, parent: INodeNo, name: &str) -> Result<(), Errno> {
        let name = c_name(name)?;
        self.call(fuse_opcode::FUSE_UNLINK, parent, &[&name])
            .map(drop)
    }

    pub(crate) fn rmdir(&self, parent: INodeNo, name: &str) -> Result<(), Errno> {
        let name = c_name(name)?;
        self.call(fuse_opcode::FUSE_RMDIR, parent, &[&name])
            .map(drop)
    }

    /// Rename `name` in `parent` to `newname` in `newparent`, replacing what is there
    pub(crate) fn rename(
        &self,
        parent: INodeNo,
        name: &str,
        newparent: INodeNo,
        newname: &str,
    ) -> Result<(), Errno> {
        let (name, newname) = (c_name(name)?, c_name(newname)?);
        // The plain layout: INIT does not offer FUSE_RENAME_SWAP, which on macOS would select
        // macFUSE's extended one
        let arg = fuse_rename_in {
            newdir: newparent.0,
        };
        self.call(
            fuse_opcode::FUSE_RENAME,
            parent,
            &[arg.as_bytes(), &name, &newname],
        )
        .map(drop)
    }

    pub(crate) fn statfs(&self, node: INodeNo) -> Result<StatFs, Errno> {
        let reply = self.call(fuse_opcode::FUSE_STATFS, node, &[])?;
        let (out, _) = fuse_statfs_out::read_from_prefix(&reply).map_err(|_| Errno::EIO)?;
        let fuse_kstatfs {
            blocks,
            bfree,
            bavail,
            bsize,
            namelen,
            frsize,
            ..
        } = out.st;
        Ok(StatFs {
            blocks,
            bfree,
            bavail,
            bsize,
            namelen,
            frsize,
        })
    }

    /// The directory at `path`, from the root, looked up as needed
    pub(crate) fn resolve_dir(&self, path: &[&str]) -> Result<INodeNo, Errno> {
        match self.resolve_dir_cached(path, true) {
            Ok(dir) => Ok(dir),
            // Retry without what was cached, which may be stale
            Err((_, true)) => {
                self.forget_path(&[]);
                self.resolve_dir_cached(path, false)
                    .map_err(|(errno, _)| errno)
            }
            Err((errno, false)) => Err(errno),
        }
    }

    /// The error comes with whether a cached directory was used on the way
    fn resolve_dir_cached(&self, path: &[&str], use_cache: bool) -> Result<INodeNo, (Errno, bool)> {
        let mut dir = INodeNo::ROOT;
        let mut used_cache = false;
        for depth in 1..=path.len() {
            let key: Vec<String> = path[..depth].iter().map(|c| (*c).to_owned()).collect();
            if use_cache {
                if let Some(cached) = self.dirs().get(&key) {
                    dir = *cached;
                    used_cache = true;
                    continue;
                }
            }
            let found = self
                .lookup(dir, path[depth - 1])
                .map_err(|errno| (errno, used_cache))?;
            if found.attr.kind != FileType::Directory {
                return Err((Errno::ENOTDIR, used_cache));
            }
            dir = found.id;
            self.dirs().insert(key, dir);
        }
        Ok(dir)
    }

    /// The file or directory at `path`, from the root. The root itself is looked up with
    /// GETATTR.
    pub(crate) fn resolve(&self, path: &[&str]) -> Result<Node, PathError> {
        let Some((last, parent_path)) = path.split_last() else {
            return self
                .getattr(INodeNo::ROOT, None)
                .map(|attr| Node {
                    id: INodeNo::ROOT,
                    attr,
                })
                .map_err(PathError::Last);
        };
        let parent = self.resolve_dir(parent_path).map_err(PathError::Parent)?;
        match self.lookup(parent, last) {
            Err(Errno::ENOENT | Errno::ESTALE) if self.is_cached(parent_path) => {
                // The parent may be stale: look it up afresh, once
                self.forget_path(parent_path);
                let parent = self.resolve_dir(parent_path).map_err(PathError::Parent)?;
                self.lookup(parent, last).map_err(PathError::Last)
            }
            result => result.map_err(PathError::Last),
        }
    }

    fn dirs(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<String>, INodeNo>> {
        self.dirs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn is_cached(&self, path: &[&str]) -> bool {
        !path.is_empty() && {
            let key: Vec<String> = path.iter().map(|c| (*c).to_owned()).collect();
            self.dirs().contains_key(&key)
        }
    }

    /// Drop what is cached for `path` and everything under it, after it was renamed or
    /// removed
    pub(crate) fn forget_path(&self, path: &[&str]) {
        self.dirs().retain(|key, _| {
            !(key.len() >= path.len() && key.iter().zip(path).all(|(a, b)| a == b))
        });
    }
}

/// A name as FUSE requests carry it: NUL terminated
fn c_name(name: &str) -> Result<Vec<u8>, Errno> {
    if name.is_empty() || name.contains('\0') || name.contains('/') {
        return Err(Errno::EINVAL);
    }
    let mut bytes = Vec::with_capacity(name.len() + 1);
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    Ok(bytes)
}

/// The payload of a reply, or the error it carries
fn decode_reply(reply: Vec<u8>) -> Result<Vec<u8>, Errno> {
    let (out, payload) = fuse_out_header::read_from_prefix(&reply).map_err(|_| Errno::EIO)?;
    if out.error != 0 {
        return Err(Errno::from_i32(-out.error));
    }
    Ok(payload.to_vec())
}

fn node(reply: &[u8]) -> Result<Node, Errno> {
    let (entry, _) = fuse_entry_out::read_from_prefix(reply).map_err(|_| Errno::EIO)?;
    if entry.nodeid == 0 {
        // A negative entry: cached absence, which is what ENOENT means here
        return Err(Errno::ENOENT);
    }
    Ok(Node {
        id: INodeNo(entry.nodeid),
        attr: file_attr(&entry.attr),
    })
}

fn attr_out(reply: &[u8]) -> Result<FileAttr, Errno> {
    let (out, _) = fuse_attr_out::read_from_prefix(reply).map_err(|_| Errno::EIO)?;
    Ok(file_attr(&out.attr))
}

/// The file type of a `st_mode`, `S_IFMT` bits only
fn file_type(mode: u32) -> Option<FileType> {
    #[allow(clippy::unnecessary_cast)]
    let kind = match mode & libc::S_IFMT as u32 {
        x if x == libc::S_IFIFO as u32 => FileType::NamedPipe,
        x if x == libc::S_IFCHR as u32 => FileType::CharDevice,
        x if x == libc::S_IFBLK as u32 => FileType::BlockDevice,
        x if x == libc::S_IFDIR as u32 => FileType::Directory,
        x if x == libc::S_IFREG as u32 => FileType::RegularFile,
        x if x == libc::S_IFLNK as u32 => FileType::Symlink,
        x if x == libc::S_IFSOCK as u32 => FileType::Socket,
        _ => return None,
    };
    Some(kind)
}

fn file_attr(attr: &fuse_attr) -> FileAttr {
    #[cfg(target_os = "macos")]
    let (crtime, flags) = (
        system_time_from_time(attr.crtime as i64, attr.crtimensec),
        attr.flags,
    );
    #[cfg(not(target_os = "macos"))]
    let (crtime, flags) = (std::time::UNIX_EPOCH, 0);
    FileAttr {
        ino: INodeNo(attr.ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: system_time_from_time(attr.atime, attr.atimensec),
        mtime: system_time_from_time(attr.mtime, attr.mtimensec),
        ctime: system_time_from_time(attr.ctime, attr.ctimensec),
        crtime,
        kind: file_type(attr.mode).unwrap_or(FileType::RegularFile),
        perm: (attr.mode & 0o7777) as u16,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
        flags,
    }
}

/// Decode the `fuse_dirent` records of a READDIR reply. Each is padded to 8 bytes.
fn dir_entries(mut data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    while let Ok((dirent, rest)) = fuse_dirent::read_from_prefix(data) {
        let namelen = dirent.namelen as usize;
        let Some(name) = rest.get(..namelen) else {
            break;
        };
        entries.push(DirEntry {
            ino: dirent.ino,
            offset: dirent.off,
            name: OsString::from_vec(name.to_vec()),
        });
        let record = (size_of::<fuse_dirent>() + namelen).next_multiple_of(8);
        data = data.get(record..).unwrap_or_default();
    }
    entries
}
