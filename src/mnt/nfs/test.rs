//! The NFS server, called with RPC messages as a client would send them, against a real session
//! over the in-process transport, with an in-memory filesystem behind it.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use parking_lot::Mutex;

use super::fuse::Fuse;
use super::nfs3::Nfs;
use super::rpc;
use super::rpc::Server;
use super::transport::Caller;
use super::transport::Transport;
use super::xdr::Reader;
use super::xdr::Writer;
use crate::Config;
use crate::Errno;
use crate::FileAttr;
use crate::FileHandle;
use crate::FileType;
use crate::Filesystem;
use crate::FopenFlags;
use crate::Generation;
use crate::INodeNo;
use crate::KernelConfig;
use crate::LockOwner;
use crate::MountOption;
use crate::OpenFlags;
use crate::Owner;
use crate::RenameFlags;
use crate::ReplyAttr;
use crate::ReplyCreate;
use crate::ReplyData;
use crate::ReplyDirectory;
use crate::ReplyEmpty;
use crate::ReplyEntry;
use crate::ReplyOpen;
use crate::ReplyStatfs;
use crate::ReplyWrite;
use crate::Request;
use crate::Session;
use crate::SessionACL;
use crate::TimeOrNow;
use crate::WriteFlags;
use crate::channel::Channel;
use crate::dev_fuse::DevFuse;

const TTL: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Node {
    attr: FileAttr,
    parent: u64,
    data: Vec<u8>,
    children: BTreeMap<OsString, u64>,
    target: OsString,
}

/// What the tests look at after the session has the filesystem
#[derive(Debug, Default)]
struct Counters {
    /// File handles open now
    open: AtomicU64,
    /// The largest write received
    largest_write: AtomicU64,
    fsyncs: AtomicU64,
    destroyed: AtomicBool,
}

/// Just enough of a filesystem to answer what the NFS procedures send
#[derive(Debug)]
struct MemFs {
    nodes: Mutex<HashMap<u64, Node>>,
    next_ino: AtomicU64,
    counters: Arc<Counters>,
}

impl MemFs {
    fn new(counters: Arc<Counters>) -> Self {
        let fs = MemFs {
            nodes: Mutex::default(),
            next_ino: AtomicU64::new(2),
            counters,
        };
        let root = fs.node(1, 1, FileType::Directory, 0o755);
        fs.nodes.lock().insert(1, root);
        fs
    }

    fn node(&self, ino: u64, parent: u64, kind: FileType, perm: u16) -> Node {
        Node {
            attr: FileAttr {
                ino: INodeNo(ino),
                size: 0,
                blocks: 0,
                atime: UNIX_EPOCH,
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
                kind,
                perm,
                nlink: 1,
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
                rdev: 0,
                flags: 0,
                blksize: 4096,
            },
            parent,
            data: Vec::new(),
            children: BTreeMap::new(),
            target: OsString::new(),
        }
    }

    fn add(&self, parent: u64, name: &OsStr, kind: FileType, perm: u16) -> Result<FileAttr, Errno> {
        let mut nodes = self.nodes.lock();
        let dir = nodes.get(&parent).ok_or(Errno::ENOENT)?;
        if dir.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let node = self.node(ino, parent, kind, perm);
        let attr = node.attr;
        nodes.insert(ino, node);
        nodes
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(name.to_owned(), ino);
        Ok(attr)
    }

    fn remove(&self, parent: u64, name: &OsStr, dir: bool) -> Result<(), Errno> {
        let mut nodes = self.nodes.lock();
        let ino = *nodes
            .get(&parent)
            .and_then(|p| p.children.get(name))
            .ok_or(Errno::ENOENT)?;
        let node = &nodes[&ino];
        match (dir, node.attr.kind == FileType::Directory) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if !node.children.is_empty() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        nodes.get_mut(&parent).unwrap().children.remove(name);
        Ok(())
    }
}

impl Filesystem for MemFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // Small, so that a large NFS write must be split
        config.set_max_write(4096).unwrap();
        Ok(())
    }

    fn destroy(&self) {
        self.counters.destroyed.store(true, Ordering::SeqCst);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let nodes = self.nodes.lock();
        match nodes
            .get(&parent.0)
            .and_then(|p| p.children.get(name))
            .map(|ino| nodes[ino].attr)
        {
            Some(attr) => reply.entry(&TTL, &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.nodes.lock().get(&ino.0) {
            Some(node) => reply.attr(&TTL, &node.attr),
            None => reply.error(Errno::ENOENT),
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
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<crate::BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        let mut nodes = self.nodes.lock();
        let Some(node) = nodes.get_mut(&ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let time = |t: TimeOrNow| match t {
            TimeOrNow::SpecificTime(t) => t,
            TimeOrNow::Now => SystemTime::now(),
        };
        if let Some(mode) = mode {
            node.attr.perm = (mode & 0o7777) as u16;
        }
        if let Some(uid) = uid {
            node.attr.uid = uid;
        }
        if let Some(gid) = gid {
            node.attr.gid = gid;
        }
        if let Some(size) = size {
            node.data.resize(size as usize, 0);
            node.attr.size = size;
        }
        if let Some(atime) = atime {
            node.attr.atime = time(atime);
        }
        if let Some(mtime) = mtime {
            node.attr.mtime = time(mtime);
        }
        reply.attr(&TTL, &node.attr);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.nodes.lock().get(&ino.0) {
            Some(node) => reply.data(node.target.as_bytes()),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        match self.add(parent.0, name, FileType::Directory, (mode & 0o7777) as u16) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.remove(parent.0, name, false) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.remove(parent.0, name, true) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        match self.add(parent.0, link_name, FileType::Symlink, 0o777) {
            Ok(attr) => {
                self.nodes.lock().get_mut(&attr.ino.0).unwrap().target =
                    target.as_os_str().to_owned();
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        _owner: Option<Owner>,
        reply: ReplyEmpty,
    ) {
        let mut nodes = self.nodes.lock();
        let Some(ino) = nodes
            .get_mut(&parent.0)
            .and_then(|p| p.children.remove(name))
        else {
            reply.error(Errno::ENOENT);
            return;
        };
        nodes
            .get_mut(&newparent.0)
            .unwrap()
            .children
            .insert(newname.to_owned(), ino);
        nodes.get_mut(&ino).unwrap().parent = newparent.0;
        reply.ok();
    }

    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        let nodes = self.nodes.lock();
        let Some(node) = nodes.get(&ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        // Owner permissions only, which is all the tests need
        let access = flags.0 & libc::O_ACCMODE;
        let needs = match access {
            libc::O_RDONLY => 0o400,
            libc::O_WRONLY => 0o200,
            _ => 0o600,
        };
        if node.attr.perm & needs != needs {
            reply.error(Errno::EACCES);
            return;
        }
        self.counters.open.fetch_add(1, Ordering::SeqCst);
        reply.opened(FileHandle(ino.0), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let nodes = self.nodes.lock();
        let data = &nodes[&ino.0].data;
        let start = (offset as usize).min(data.len());
        let end = (start + size as usize).min(data.len());
        reply.data(&data[start..end]);
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        self.counters
            .largest_write
            .fetch_max(data.len() as u64, Ordering::SeqCst);
        let mut nodes = self.nodes.lock();
        let node = nodes.get_mut(&ino.0).unwrap();
        let end = offset as usize + data.len();
        if node.data.len() < end {
            node.data.resize(end, 0);
        }
        node.data[offset as usize..end].copy_from_slice(data);
        node.attr.size = node.data.len() as u64;
        reply.written(data.len() as u32);
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.counters.fsyncs.fetch_add(1, Ordering::SeqCst);
        reply.ok();
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
        self.counters.open.fetch_sub(1, Ordering::SeqCst);
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let nodes = self.nodes.lock();
        let node = &nodes[&ino.0];
        let mut entries = vec![
            (ino.0, FileType::Directory, OsString::from(".")),
            (node.parent, FileType::Directory, OsString::from("..")),
        ];
        for (name, child) in &node.children {
            entries.push((*child, nodes[child].attr.kind, name.clone()));
        }
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(ino), i as u64 + 1, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        _kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        match self.add(
            parent.0,
            name,
            FileType::RegularFile,
            (mode & 0o7777) as u16,
        ) {
            Ok(attr) => {
                self.counters.open.fetch_add(1, Ordering::SeqCst);
                reply.created(
                    &TTL,
                    &attr,
                    Generation(0),
                    FileHandle(attr.ino.0),
                    FopenFlags::empty(),
                );
            }
            Err(e) => reply.error(e),
        }
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let mut nodes = self.nodes.lock();
        if nodes[&newparent.0].children.contains_key(newname) {
            return reply.error(Errno::EEXIST);
        }
        let node = nodes.get_mut(&ino.0).unwrap();
        node.attr.nlink += 1;
        let attr = node.attr;
        nodes
            .get_mut(&newparent.0)
            .unwrap()
            .children
            .insert(newname.to_owned(), ino.0);
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        // S_IFMT, S_IFIFO and S_IFCHR, whose type differs between platforms
        let kind = match mode & 0o170000 {
            0o010000 => FileType::NamedPipe,
            0o020000 => FileType::CharDevice,
            _ => return reply.error(Errno::EINVAL),
        };
        match self.add(parent.0, name, kind, (mode & 0o7777) as u16) {
            Ok(mut attr) => {
                attr.rdev = rdev;
                self.nodes.lock().get_mut(&attr.ino.0).unwrap().attr.rdev = rdev;
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(e) => reply.error(e),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(100, 50, 40, 10, 5, 512, NAME_MAX, 4096);
    }
}

/// Not the usual 255, to tell it from a default
const NAME_MAX: u32 = 1000;

const NFS: u32 = 100003;
const MOUNT: u32 = 100005;

// NFS procedures
const GETATTR: u32 = 1;
const SETATTR: u32 = 2;
const LOOKUP: u32 = 3;
const ACCESS: u32 = 4;
const READLINK: u32 = 5;
const READ: u32 = 6;
const WRITE: u32 = 7;
const CREATE: u32 = 8;
const MKDIR: u32 = 9;
const SYMLINK: u32 = 10;
const MKNOD: u32 = 11;
const REMOVE: u32 = 12;
const RMDIR: u32 = 13;
const RENAME: u32 = 14;
const LINK: u32 = 15;
const READDIR: u32 = 16;
const READDIRPLUS: u32 = 17;
const FSSTAT: u32 = 18;
const FSINFO: u32 = 19;
const PATHCONF: u32 = 20;
const COMMIT: u32 = 21;

const ROOT: u64 = 1;

/// A session on a `MemFs`, and an NFS server for it
struct Harness {
    fuse: Fuse,
    nfs: Nfs,
    counters: Arc<Counters>,
    background: crate::BackgroundSession,
    xid: u32,
}

fn start(read_only: bool) -> Harness {
    let transport = Arc::new(Transport::default());
    let caller = Caller {
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
    };
    let fuse = Fuse::new(transport.clone(), caller);
    let init = fuse.start_init().unwrap();
    let counters = Arc::new(Counters::default());
    let device = Arc::new(DevFuse::from_transport(transport).unwrap());
    // Owner: the requests carry the mounting user's ids, which this checks
    let session = Session::from_channel(
        MemFs::new(counters.clone()),
        Channel::new(device),
        SessionACL::Owner,
        Config::default(),
    )
    .unwrap();
    let background = session.spawn().unwrap();
    fuse.finish_init(&init).unwrap();
    let nfs = Nfs::new(fuse.clone(), read_only, "export").unwrap();
    KEY.set(nfs.handle_key());
    Harness {
        nfs,
        fuse,
        counters,
        background,
        xid: 0,
    }
}

fn call_message(xid: u32, program: u32, version: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    let mut call = Vec::new();
    call.put_u32(xid);
    // CALL, RPC version 2
    call.put_u32(0);
    call.put_u32(2);
    call.put_u32(program);
    call.put_u32(version);
    call.put_u32(procedure);
    // AUTH_UNIX credentials, then an AUTH_NONE verifier
    call.put_u32(1);
    call.put_opaque(&[0; 20]);
    call.put_u32(0);
    call.put_opaque(&[]);
    call.extend_from_slice(args);
    call
}

/// Checks the header of a reply to `xid`, returning its accept_stat and what follows
fn accepted(reply: &[u8], xid: u32) -> (u32, Vec<u8>) {
    let mut r = Reader::new(reply);
    assert_eq!(r.u32(), Ok(xid));
    // REPLY, MSG_ACCEPTED, AUTH_NONE verifier
    assert_eq!(r.u32(), Ok(1));
    assert_eq!(r.u32(), Ok(0));
    assert_eq!(r.u32(), Ok(0));
    assert_eq!(r.opaque(), Ok(&[][..]));
    let stat = r.u32().unwrap();
    (stat, r.rest().to_vec())
}

impl Harness {
    /// Calls a procedure, returning its results
    fn call(&mut self, program: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
        self.xid += 1;
        let reply = rpc::answer(
            &self.nfs,
            &call_message(self.xid, program, 3, procedure, args),
        )
        .unwrap();
        let (stat, results) = accepted(&reply, self.xid);
        assert_eq!(stat, 0, "procedure {procedure} not answered");
        results
    }

    /// Calls an NFS procedure that succeeds, returning what follows its status
    fn ok(&mut self, procedure: u32, args: &[u8]) -> Vec<u8> {
        let results = self.call(NFS, procedure, args);
        let mut r = Reader::new(&results);
        assert_eq!(r.u32(), Ok(0), "status of procedure {procedure}");
        r.rest().to_vec()
    }

    /// Calls an NFS procedure that fails, returning its status, after checking that only
    /// absent attributes follow it
    fn fails(&mut self, procedure: u32, args: &[u8]) -> u32 {
        let results = self.call(NFS, procedure, args);
        let mut r = Reader::new(&results);
        let status = r.u32().unwrap();
        assert_ne!(status, 0, "procedure {procedure} succeeded");
        assert!(r.rest().iter().all(|&b| b == 0));
        status
    }

    /// Ends the session, checking that every file handle was released
    fn finish(self) {
        self.fuse.shutdown();
        self.background.join().unwrap();
        assert!(self.counters.destroyed.load(Ordering::SeqCst));
        assert_eq!(self.counters.open.load(Ordering::SeqCst), 0);
    }
}

#[derive(Debug)]
struct Fattr {
    ftype: u32,
    mode: u32,
    nlink: u32,
    size: u64,
    rdev: (u32, u32),
    atime: (u32, u32),
    mtime: (u32, u32),
}

fn fattr(r: &mut Reader<'_>) -> Fattr {
    let ftype = r.u32().unwrap();
    let mode = r.u32().unwrap();
    let nlink = r.u32().unwrap();
    // uid, gid
    r.u32().unwrap();
    r.u32().unwrap();
    let size = r.u64().unwrap();
    // used
    r.u64().unwrap();
    let rdev = (r.u32().unwrap(), r.u32().unwrap());
    // fsid, fileid
    r.u64().unwrap();
    r.u64().unwrap();
    let atime = (r.u32().unwrap(), r.u32().unwrap());
    let mtime = (r.u32().unwrap(), r.u32().unwrap());
    // ctime
    r.u64().unwrap();
    Fattr {
        ftype,
        mode,
        nlink,
        size,
        rdev,
        atime,
        mtime,
    }
}

fn post_op(r: &mut Reader<'_>) -> Option<Fattr> {
    r.bool().unwrap().then(|| fattr(r))
}

/// The node id a file handle names
fn handle(r: &mut Reader<'_>) -> u64 {
    u64::from_be_bytes(r.opaque().unwrap()[..8].try_into().unwrap())
}

/// Reads CREATE, MKDIR, SYMLINK or MKNOD results: the new handle and attributes
fn created(results: &[u8]) -> (u64, Fattr) {
    let mut r = Reader::new(results);
    assert!(r.bool().unwrap());
    let node = handle(&mut r);
    let attr = post_op(&mut r).unwrap();
    (node, attr)
}

fn args(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut a = Vec::new();
    f(&mut a);
    a
}

thread_local! {
    /// The key of the server the test on this thread talks to
    static KEY: std::cell::Cell<[u8; 8]> = const { std::cell::Cell::new([0; 8]) };
}

fn put_handle(a: &mut Vec<u8>, node: u64) {
    a.put_opaque(&[&node.to_be_bytes()[..], &KEY.get()].concat());
}

fn dirop(dir: u64, name: &str) -> Vec<u8> {
    args(|a| {
        put_handle(a, dir);
        a.put_opaque(name.as_bytes());
    })
}

/// sattr3 setting the mode, or nothing
fn put_sattr(a: &mut Vec<u8>, mode: Option<u32>) {
    a.put_bool(mode.is_some());
    if let Some(mode) = mode {
        a.put_u32(mode);
    }
    // uid, gid, size, atime, mtime
    for _ in 0..5 {
        a.put_u32(0);
    }
}

#[test]
fn nfs_procedures_reach_the_filesystem() {
    let mut h = start(false);

    let mut r_args = args(|a| put_handle(a, ROOT));
    let root = fattr(&mut Reader::new(&h.ok(GETATTR, &r_args)));
    assert_eq!(root.ftype, 2);

    // Directories, created with the mode asked for
    let mut a = dirop(ROOT, "dir");
    put_sattr(&mut a, Some(0o750));
    let (dir, attr) = created(&h.ok(MKDIR, &a));
    assert_eq!((attr.ftype, attr.mode), (2, 0o750));
    assert_eq!(h.fails(MKDIR, &a), 17);
    for (name, expected) in [("dir", dir), (".", ROOT)] {
        let results = h.ok(LOOKUP, &dirop(ROOT, name));
        assert_eq!(handle(&mut Reader::new(&results)), expected);
    }
    for (name, expected) in [("..", ROOT), (".", dir)] {
        let results = h.ok(LOOKUP, &dirop(dir, name));
        assert_eq!(handle(&mut Reader::new(&results)), expected);
    }
    assert_eq!(h.fails(LOOKUP, &dirop(ROOT, "missing")), 2);

    // A file created without write permission can still be written through the handle
    // that created it, as a local open(O_CREAT) followed by write(2) can
    let mut a = dirop(dir, "file");
    // GUARDED
    a.put_u32(1);
    put_sattr(&mut a, Some(0o444));
    let (file, attr) = created(&h.ok(CREATE, &a));
    assert_eq!((attr.ftype, attr.mode), (1, 0o444));
    assert_eq!(h.fails(CREATE, &a), 17);
    let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    let results = h.ok(
        WRITE,
        &args(|a| {
            put_handle(a, file);
            a.put_u64(0);
            a.put_u32(data.len() as u32);
            // UNSTABLE
            a.put_u32(0);
            a.put_opaque(&data);
        }),
    );
    let mut r = Reader::new(&results);
    // No wcc_data
    assert_eq!((r.bool(), r.bool()), (Ok(false), Ok(false)));
    assert_eq!((r.u32(), r.u32()), (Ok(10_000), Ok(0)));
    let verifier = r.fixed(8).unwrap().to_vec();
    assert_eq!(h.counters.fsyncs.load(Ordering::SeqCst), 0);
    // Split at the session's max_write
    assert_eq!(h.counters.largest_write.load(Ordering::SeqCst), 4096);
    for (offset, count, expected, eof) in [
        (0, 6000, &data[..6000], false),
        (6000, 6000, &data[6000..], true),
    ] {
        let results = h.ok(
            READ,
            &args(|a| {
                put_handle(a, file);
                a.put_u64(offset);
                a.put_u32(count);
            }),
        );
        let mut r = Reader::new(&results);
        assert!(post_op(&mut r).is_none());
        assert_eq!(r.u32(), Ok(expected.len() as u32));
        assert_eq!(r.bool(), Ok(eof));
        assert_eq!(r.opaque(), Ok(expected));
    }
    let results = h.ok(
        COMMIT,
        &args(|a| {
            put_handle(a, file);
            a.put_u64(0);
            a.put_u32(0);
        }),
    );
    assert_eq!(&results[8..], &verifier[..]);
    // The COMMIT reached the filesystem's fsync, as does a stable write
    assert_eq!(h.counters.fsyncs.load(Ordering::SeqCst), 1);
    let results = h.ok(
        WRITE,
        &args(|a| {
            put_handle(a, file);
            a.put_u64(0);
            a.put_u32(1);
            // FILE_SYNC
            a.put_u32(2);
            a.put_opaque(&data[..1]);
        }),
    );
    assert_eq!(&results[8..16], [0, 0, 0, 1, 0, 0, 0, 2]);
    assert_eq!(h.counters.fsyncs.load(Ordering::SeqCst), 2);
    let mut a = dirop(dir, "file");
    // EXCLUSIVE, with its verifier
    a.put_u32(2);
    a.put_fixed(&[7; 8]);
    assert_eq!(h.fails(CREATE, &a), 17);

    // Attributes
    let results = h.ok(
        SETATTR,
        &args(|a| {
            put_handle(a, file);
            a.put_bool(true);
            a.put_u32(0o640);
            // uid, gid
            a.put_bool(false);
            a.put_bool(false);
            a.put_bool(true);
            a.put_u64(5);
            // SET_TO_CLIENT_TIME
            a.put_u32(2);
            a.put_u32(1000);
            a.put_u32(7);
            a.put_u32(2);
            a.put_u32(2000);
            a.put_u32(9);
            // No guard
            a.put_bool(false);
        }),
    );
    let mut r = Reader::new(&results);
    assert_eq!(r.bool(), Ok(false));
    let attr = post_op(&mut r).unwrap();
    assert_eq!((attr.mode, attr.size), (0o640, 5));
    assert_eq!((attr.atime, attr.mtime), ((1000, 7), (2000, 9)));
    let results = h.ok(
        ACCESS,
        &args(|a| {
            put_handle(a, file);
            a.put_u32(0x3f);
        }),
    );
    assert_eq!(&results[4..], 0x3fu32.to_be_bytes());

    // Symlinks, hard links and special files
    let mut a = dirop(dir, "link");
    put_sattr(&mut a, None);
    a.put_opaque(b"file");
    let (link, attr) = created(&h.ok(SYMLINK, &a));
    assert_eq!(attr.ftype, 5);
    let results = h.ok(READLINK, &args(|a| put_handle(a, link)));
    assert_eq!(Reader::new(&results[4..]).opaque(), Ok(&b"file"[..]));
    let mut a = args(|a| put_handle(a, file));
    a.extend_from_slice(&dirop(dir, "hard"));
    let results = h.ok(LINK, &a);
    assert_eq!(post_op(&mut Reader::new(&results)).unwrap().nlink, 2);
    let mut a = dirop(dir, "fifo");
    a.put_u32(7);
    put_sattr(&mut a, Some(0o600));
    let (_, attr) = created(&h.ok(MKNOD, &a));
    assert_eq!((attr.ftype, attr.mode), (7, 0o600));
    let mut a = dirop(dir, "chr");
    a.put_u32(4);
    put_sattr(&mut a, Some(0o600));
    a.put_u32(1);
    a.put_u32(2);
    let (_, attr) = created(&h.ok(MKNOD, &a));
    assert_eq!((attr.ftype, attr.rdev), (4, (1, 2)));
    let mut a = dirop(dir, "reg");
    a.put_u32(1);
    assert_eq!(h.fails(MKNOD, &a), 10007);

    // Listing a directory a page at a time, resuming at each page's last cookie
    for i in 0..20 {
        let mut a = dirop(ROOT, &format!("f{i:02}"));
        a.put_u32(0);
        put_sattr(&mut a, None);
        h.ok(CREATE, &a);
    }
    let mut names = Vec::new();
    let mut cookie = 0;
    loop {
        let results = h.ok(
            READDIRPLUS,
            &args(|a| {
                put_handle(a, ROOT);
                a.put_u64(cookie);
                a.put_fixed(&[0; 8]);
                a.put_u32(1000);
                a.put_u32(1000);
            }),
        );
        let mut r = Reader::new(&results);
        assert!(post_op(&mut r).is_none());
        r.fixed(8).unwrap();
        let before = names.len();
        while r.bool().unwrap() {
            r.u64().unwrap();
            names.push(String::from_utf8(r.opaque().unwrap().to_vec()).unwrap());
            cookie = r.u64().unwrap();
            assert!(post_op(&mut r).is_some());
            assert!(r.bool().unwrap());
            handle(&mut r);
        }
        assert!(names.len() > before);
        if r.bool().unwrap() {
            break;
        }
    }
    // "." and "..", as the filesystem lists them, with handles and attributes like the rest
    let mut expected: Vec<String> = (0..20).map(|i| format!("f{i:02}")).collect();
    for name in ["dir", "..", "."] {
        expected.insert(0, name.to_string());
    }
    assert_eq!(names, expected);
    let readdir = |count: u32| {
        args(|a| {
            put_handle(a, ROOT);
            a.put_u64(0);
            a.put_fixed(&[0; 8]);
            a.put_u32(count);
        })
    };
    let results = h.ok(READDIR, &readdir(100_000));
    // eof, after the end of the list
    assert_eq!(&results[results.len() - 8..], [0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(h.fails(READDIR, &readdir(30)), 10005);

    // Renaming into another directory, and removing
    let mut a = dirop(ROOT, "f00");
    a.extend_from_slice(&dirop(dir, "moved"));
    h.ok(RENAME, &a);
    h.ok(LOOKUP, &dirop(dir, "moved"));
    assert_eq!(h.fails(RMDIR, &dirop(ROOT, "dir")), 66);
    assert_eq!(h.fails(REMOVE, &dirop(ROOT, "dir")), 21);
    for name in ["file", "link", "hard", "moved", "fifo", "chr"] {
        h.ok(REMOVE, &dirop(dir, name));
    }
    h.ok(RMDIR, &dirop(ROOT, "dir"));
    assert_eq!(h.fails(LOOKUP, &dirop(ROOT, "dir")), 2);

    // What the filesystem is
    r_args = args(|a| put_handle(a, ROOT));
    let results = h.ok(FSINFO, &r_args);
    let mut r = Reader::new(&results[4..]);
    assert_eq!(r.u32(), Ok(1024 * 1024));
    let results = h.ok(FSSTAT, &r_args);
    let mut r = Reader::new(&results[4..]);
    assert_eq!(
        (r.u64(), r.u64(), r.u64()),
        (Ok(409_600), Ok(204_800), Ok(163_840))
    );
    // PATHCONF reports the filesystem's own name limit, which clients enforce and size
    // their names by
    let results = h.ok(PATHCONF, &r_args);
    let mut r = Reader::new(&results[8..]);
    assert_eq!(r.u32(), Ok(NAME_MAX));

    h.finish();
}

#[test]
fn rpc_errors() {
    let h = start(false);
    let answer = |call: &[u8]| rpc::answer(&h.nfs, call).unwrap();

    let mut call = call_message(1, NFS, 3, 0, &[]);
    // RPC version 3: MSG_DENIED, RPC_MISMATCH 2 to 2
    call[8..12].copy_from_slice(&3u32.to_be_bytes());
    assert_eq!(
        &answer(&call)[4..],
        [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2]
    );
    // A reply is not answered
    call[4..8].copy_from_slice(&1u32.to_be_bytes());
    assert!(rpc::answer(&h.nfs, &call).is_none());

    let (stat, rest) = accepted(&answer(&call_message(2, 100_000, 2, 3, &[])), 2);
    assert_eq!((stat, rest.len()), (1, 0));
    let (stat, rest) = accepted(&answer(&call_message(3, NFS, 4, 0, &[])), 3);
    assert_eq!((stat, &rest[..]), (2, &[0, 0, 0, 3, 0, 0, 0, 3][..]));
    let (stat, _) = accepted(&answer(&call_message(4, NFS, 3, 22, &[])), 4);
    assert_eq!(stat, 3);
    // Handles that are not this server's: too short, or with another key
    for handle in [
        &b"abc"[..],
        &[0, 0, 0, 0, 0, 0, 0, 1, 9, 9, 9, 9, 9, 9, 9, 9],
    ] {
        let (stat, rest) = accepted(
            &answer(&call_message(
                5,
                NFS,
                3,
                GETATTR,
                &args(|a| a.put_opaque(handle)),
            )),
            5,
        );
        // NFS3ERR_BADHANDLE
        assert_eq!((stat, &rest[..]), (0, &10001u32.to_be_bytes()[..]));
    }
    let (stat, rest) = accepted(&answer(&call_message(6, NFS, 3, 0, &[])), 6);
    assert_eq!((stat, rest.len()), (0, 0));
    h.finish();
}

#[test]
fn mount_protocol() {
    let mut h = start(false);
    let results = h.call(MOUNT, 1, &args(|a| a.put_opaque(b"/export")));
    let mut r = Reader::new(&results);
    assert_eq!(r.u32(), Ok(0));
    assert_eq!(handle(&mut r), ROOT);
    // AUTH_UNIX
    assert_eq!((r.u32(), r.u32()), (Ok(1), Ok(1)));
    // Again, as some clients ask, until the mount is in use: then no one else gets a handle
    let again = h.call(MOUNT, 1, &args(|a| a.put_opaque(b"/export")));
    assert_eq!(again, results);
    h.ok(GETATTR, &args(|a| put_handle(a, ROOT)));
    let results = h.call(MOUNT, 1, &args(|a| a.put_opaque(b"/export")));
    assert_eq!(results, 13u32.to_be_bytes());
    let results = h.call(MOUNT, 5, &[]);
    let mut r = Reader::new(&results);
    assert_eq!(r.bool(), Ok(true));
    assert_eq!(r.opaque(), Ok(&b"/export"[..]));
    assert_eq!((r.bool(), r.bool()), (Ok(false), Ok(false)));
    assert!(
        h.call(MOUNT, 3, &args(|a| a.put_opaque(b"/export")))
            .is_empty()
    );
    h.finish();
}

#[test]
fn read_only_refuses_changes() {
    let mut h = start(true);
    let mut a = dirop(ROOT, "file");
    a.put_u32(0);
    put_sattr(&mut a, None);
    assert_eq!(h.fails(CREATE, &a), 30);
    assert_eq!(h.fails(REMOVE, &dirop(ROOT, "file")), 30);
    h.ok(GETATTR, &args(|a| put_handle(a, ROOT)));
    h.finish();
}

#[test]
fn idle_handles_are_released() {
    let mut h = start(false);
    let mut a = dirop(ROOT, "f");
    a.put_u32(0);
    put_sattr(&mut a, None);
    let (file, _) = created(&h.ok(CREATE, &a));
    let io = |a: &mut Vec<u8>| {
        put_handle(a, file);
        a.put_u64(0);
        a.put_u32(1);
    };
    h.ok(
        WRITE,
        &args(|a| {
            io(a);
            a.put_u32(2);
            a.put_opaque(b"x");
        }),
    );
    h.ok(READ, &args(io));
    // Kept for further use
    h.fuse.release_idle(Duration::from_secs(60));
    h.ok(GETATTR, &args(|a| put_handle(a, file)));
    assert_eq!(h.counters.open.load(Ordering::SeqCst), 1);
    // Released once idle. The release is answered before this later request is
    h.fuse.release_idle(Duration::ZERO);
    h.ok(GETATTR, &args(|a| put_handle(a, file)));
    assert_eq!(h.counters.open.load(Ordering::SeqCst), 0);
    h.finish();
}

#[test]
fn tcp_server_answers_and_stops() {
    let h = start(false);
    let server = Server::bind(Nfs::new(h.fuse.clone(), false, "").unwrap(), 0).unwrap();
    let port = server.port().unwrap();
    let stopper = server.stopper().unwrap();
    let running = std::thread::spawn(move || server.run());
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    for xid in 1..=3 {
        rpc::write_record(
            &mut stream,
            &call_message(xid, NFS, 3, GETATTR, &args(|a| put_handle(a, ROOT))),
        )
        .unwrap();
    }
    let mut xids: Vec<u32> = (0..3)
        .map(|_| {
            let reply = rpc::read_record(&mut stream).unwrap();
            u32::from_be_bytes(reply[..4].try_into().unwrap())
        })
        .collect();
    xids.sort_unstable();
    assert_eq!(xids, [1, 2, 3]);
    stopper.stop();
    running.join().unwrap();
    // The connection was ended too
    assert!(rpc::read_record(&mut stream).is_err());
    h.finish();
}

#[test]
fn mount_options_map_to_mount_nfs() {
    let opts = super::mount_nfs_options(
        &[
            MountOption::RO,
            MountOption::NoSuid,
            MountOption::FSName("hello".to_string()),
            MountOption::CUSTOM("rsize=4096".to_string()),
            MountOption::DefaultPermissions,
        ],
        1234,
    );
    for expected in [
        "vers=3",
        "tcp",
        "port=1234",
        "mountport=1234",
        "rdonly",
        "nosuid",
        "rsize=4096",
    ] {
        assert!(opts.iter().any(|o| o == expected), "{expected} in {opts:?}");
    }
    assert!(
        !super::mount_nfs_options(&[], 1)
            .iter()
            .any(|o| o == "rdonly")
    );

    assert_eq!(
        super::export_name(&[MountOption::FSName("hello".to_string())]),
        "hello"
    );
    // Names the mount table would need quoted for are left out
    assert_eq!(
        super::export_name(&[MountOption::FSName("a b".to_string())]),
        ""
    );
    assert_eq!(super::export_name(&[]), "");
}
