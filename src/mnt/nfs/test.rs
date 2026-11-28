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
use crate::AccessFlags;
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
    /// Size changes that came with a file handle, as ftruncate's do
    truncates_with_handle: AtomicU64,
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
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<crate::BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        if size.is_some() && fh.is_some() {
            self.counters
                .truncates_with_handle
                .fetch_add(1, Ordering::SeqCst);
        }
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

    /// Writing needs a write bit; nothing else is refused
    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        let perm = self.nodes.lock()[&ino.0].attr.perm;
        if mask.contains(AccessFlags::W_OK) && perm & 0o222 == 0 {
            reply.error(Errno::EACCES);
        } else {
            reply.ok();
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
    /// The NFSv4.1 session COMPOUNDs are sent in, and the sequence id of its slot 0
    session: Option<[u8; 16]>,
    sequence: u32,
}

fn start(read_only: bool) -> Harness {
    start_version(read_only, false)
}

/// A harness for a mount with NFSv3, or with `v4` NFSv4.1
fn start_version(read_only: bool, v4: bool) -> Harness {
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
    let nfs = Nfs::new(fuse.clone(), read_only, "export", v4).unwrap();
    KEY.set(nfs.handle_key());
    Harness {
        nfs,
        fuse,
        counters,
        background,
        xid: 0,
        session: None,
        sequence: 0,
    }
}

fn call_message(xid: u32, program: u32, version: u32, procedure: u32, args: &[u8]) -> Vec<u8> {
    let (uid, gid) = (
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    );
    call_message_as(xid, program, version, procedure, args, uid, gid)
}

/// A call with AUTH_UNIX credentials for `uid` and `gid`
fn call_message_as(
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    args: &[u8],
    uid: u32,
    gid: u32,
) -> Vec<u8> {
    let mut credentials = Vec::new();
    // stamp, machinename, uid, gid, no supplementary groups
    credentials.put_u32(0);
    credentials.put_opaque(b"localhost");
    credentials.put_u32(uid);
    credentials.put_u32(gid);
    credentials.put_u32(0);
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
    call.put_opaque(&credentials);
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
    // wcc_data: the size and times before, then the attributes after
    assert_eq!((r.bool(), r.u64()), (Ok(true), Ok(0)));
    r.fixed(16).unwrap();
    assert_eq!(post_op(&mut r).map(|attr| attr.size), Some(10_000));
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
    // wcc_data around the sync, then the verifier the writes gave
    assert_eq!(&results[results.len() - 8..], &verifier[..]);
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
    // After the wcc_data: count, then FILE_SYNC, then the verifier
    let tail = &results[results.len() - 16..];
    assert_eq!(&tail[..8], [0, 0, 0, 1, 0, 0, 0, 2]);
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
    // The filesystem's own answer: the file has no write bits, so no MODIFY or EXTEND. DELETE
    // is its directory's to decide, at REMOVE
    let mut a = dirop(dir, "readonly");
    a.put_u32(0);
    put_sattr(&mut a, Some(0o444));
    let (readonly, _) = created(&h.ok(CREATE, &a));
    let results = h.ok(
        ACCESS,
        &args(|a| {
            put_handle(a, readonly);
            a.put_u32(0x3f);
        }),
    );
    assert_eq!(&results[4..], 0x33u32.to_be_bytes());
    h.ok(REMOVE, &dirop(dir, "readonly"));

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
    // NFS versions 3 and 4 are served
    let (stat, rest) = accepted(&answer(&call_message(3, NFS, 2, 0, &[])), 3);
    assert_eq!((stat, &rest[..]), (2, &[0, 0, 0, 3, 0, 0, 0, 4][..]));
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
fn requests_carry_the_callers_ids() {
    let h = start(false);
    let getattr = args(|a| put_handle(a, ROOT));
    let answer = |uid| {
        let gid = nix::unistd::getegid().as_raw();
        let call = call_message_as(1, NFS, 3, GETATTR, &getattr, uid, gid);
        let (stat, rest) = accepted(&rpc::answer(&h.nfs, &call).unwrap(), 1);
        assert_eq!(stat, 0);
        u32::from_be_bytes(rest[..4].try_into().unwrap())
    };
    // The session admits only the mounting user, as FUSE mounts do without allow_other: so
    // the caller's uid reached it
    assert_eq!(answer(nix::unistd::geteuid().as_raw()), 0);
    let other = nix::unistd::geteuid().as_raw().wrapping_add(4242);
    // NFS3ERR_ACCES
    assert_eq!(answer(other), 13);
    h.finish();
}

#[test]
fn mount_protocol() {
    let mut h = start(false);
    // The export's path is the filesystem's name and a secret: no other path mounts
    let export = h.nfs.export_path();
    assert!(export.starts_with("/export.") && export.len() > 20);
    let mnt = |path: &str| args(|a| a.put_opaque(path.as_bytes()));
    assert_eq!(h.call(MOUNT, 1, &mnt("/export")), 13u32.to_be_bytes());
    assert_eq!(h.call(MOUNT, 1, &mnt("/")), 13u32.to_be_bytes());
    let results = h.call(MOUNT, 1, &mnt(&export));
    let mut r = Reader::new(&results);
    assert_eq!(r.u32(), Ok(0));
    assert_eq!(handle(&mut r), ROOT);
    // AUTH_UNIX
    assert_eq!((r.u32(), r.u32()), (Ok(1), Ok(1)));
    // Again, as some clients ask, until the mount is in use: then no one else gets a handle
    let again = h.call(MOUNT, 1, &mnt(&export));
    assert_eq!(again, results);
    h.ok(GETATTR, &args(|a| put_handle(a, ROOT)));
    assert_eq!(h.call(MOUNT, 1, &mnt(&export)), 13u32.to_be_bytes());
    // EXPORT lists nothing, as the path is the secret
    assert_eq!(h.call(MOUNT, 5, &[]), [0, 0, 0, 0]);
    assert!(
        h.call(MOUNT, 3, &args(|a| a.put_opaque(b"/export")))
            .is_empty()
    );
    h.finish();
}

#[test]
fn names_are_checked() {
    let mut h = start(false);
    let create = |name: &[u8]| {
        let mut a = Vec::new();
        put_handle(&mut a, ROOT);
        a.put_opaque(name);
        a.put_u32(0);
        put_sattr(&mut a, None);
        a
    };
    // As the kernel never would: '/', NUL or nothing
    for name in [&b"a/b"[..], b"a\0b", b""] {
        assert_eq!(h.fails(CREATE, &create(name)), 22, "{name:?}");
    }
    // "." and ".." get what POSIX says, not the filesystem's say: they exist, are not files,
    // and are not empty
    for name in [&b"."[..], b".."] {
        assert_eq!(h.fails(CREATE, &create(name)), 17, "{name:?}");
        assert_eq!(
            h.fails(
                REMOVE,
                &args(|a| {
                    put_handle(a, ROOT);
                    a.put_opaque(name);
                })
            ),
            1
        );
    }
    assert_eq!(h.fails(RMDIR, &dirop(ROOT, ".")), 22);
    assert_eq!(h.fails(RMDIR, &dirop(ROOT, "..")), 66);
    // Longer than NAME_MAX
    assert_eq!(h.fails(CREATE, &create(&[b'x'; 256])), 63);
    h.ok(CREATE, &create(&[b'x'; 255]));
    // LOOKUP of ".." is how clients find a parent
    h.ok(LOOKUP, &dirop(ROOT, ".."));
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
    let server = Server::bind(Nfs::new(h.fuse.clone(), false, "", false).unwrap(), 0).unwrap();
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
        "rsize=1048576",
        "wsize=524288",
        "rsize=4096",
    ] {
        assert!(opts.iter().any(|o| o == expected), "{expected} in {opts:?}");
    }
    assert!(
        !super::mount_nfs_options(&[], 1)
            .iter()
            .any(|o| o == "rdonly")
    );
    // Attributes are cached for a second, unless the options say otherwise: mount_nfs takes
    // the last of each
    let opts = super::mount_nfs_options(&[MountOption::CUSTOM("actimeo=0".to_string())], 1);
    let actimeo: Vec<_> = opts.iter().filter(|o| o.starts_with("actimeo=")).collect();
    assert_eq!(actimeo, ["actimeo=1", "actimeo=0"]);

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
    // NFSv4.1 when asked for, without NFSv3's MOUNT program or local locks
    let v4 = super::mount_nfs_options(&[MountOption::CUSTOM("vers=4".to_string())], 1234);
    assert!(super::wants_v4(&[MountOption::CUSTOM(
        "vers=4".to_string()
    )]));
    assert_eq!(&v4[..3], ["vers=4.1", "tcp", "port=1234"]);
    assert!(v4.iter().any(|o| o == "wsize=1048576"));
    assert_eq!(
        super::mount_nfs_options(&[MountOption::CUSTOM("vers=4.1".to_string())], 1234),
        v4
    );
    assert!(
        !v4.iter()
            .any(|o| o.starts_with("mountport") || o == "locallocks" || o == "vers=3")
    );
    // Read-only: soft read-only mounts would get locallocks, which NFSv4 refuses
    let v4_ro = super::mount_nfs_options(
        &[MountOption::CUSTOM("vers=4".to_string()), MountOption::RO],
        1234,
    );
    assert!(v4_ro.iter().any(|o| o == "nolocallocks"));
    assert!(
        !super::mount_nfs_options(&[MountOption::RO], 1)
            .iter()
            .any(|o| o == "nolocallocks")
    );
}

// NFSv4.1 operations
const OP_ACCESS: u32 = 3;
const OP_CLOSE: u32 = 4;
const OP_CREATE: u32 = 6;
const OP_GETATTR: u32 = 9;
const OP_GETFH: u32 = 10;
const OP_LOCK: u32 = 12;
const OP_LOCKT: u32 = 13;
const OP_LOCKU: u32 = 14;
const OP_LOOKUP: u32 = 15;
const OP_LOOKUPP: u32 = 16;
const OP_OPEN: u32 = 18;
const OP_PUTFH: u32 = 22;
const OP_PUTROOTFH: u32 = 24;
const OP_READ: u32 = 25;
const OP_READDIR: u32 = 26;
const OP_REMOVE: u32 = 28;
const OP_RENAME: u32 = 29;
const OP_RENEW: u32 = 30;
const OP_SAVEFH: u32 = 32;
const OP_SETATTR: u32 = 34;
const OP_WRITE: u32 = 38;
const OP_EXCHANGE_ID: u32 = 42;
const OP_CREATE_SESSION: u32 = 43;
const OP_DESTROY_SESSION: u32 = 44;
const OP_FREE_STATEID: u32 = 45;
const OP_SEQUENCE: u32 = 53;
const OP_TEST_STATEID: u32 = 55;
const OP_DESTROY_CLIENTID: u32 = 57;
const OP_RECLAIM_COMPLETE: u32 = 58;

/// The current stateid, which stands for the one the last operation left
const CURRENT_STATEID: [u8; 16] = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

type Ops = Vec<(u32, Vec<u8>)>;

impl Harness {
    /// Sends a COMPOUND, the whole of whose reply is returned
    fn compound_raw(&mut self, minor: u32, ops: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut a = Vec::new();
        a.put_opaque(b"tag");
        a.put_u32(minor);
        a.put_u32(ops.len() as u32);
        for (op, args) in ops {
            a.put_u32(*op);
            a.extend_from_slice(args);
        }
        self.xid += 1;
        let reply = rpc::answer(&self.nfs, &call_message(self.xid, NFS, 4, 1, &a)).unwrap();
        let (stat, results) = accepted(&reply, self.xid);
        assert_eq!(stat, 0);
        results
    }

    /// The SEQUENCE that starts the next COMPOUND of the session, on slot 0
    fn sequence4(&mut self, cache: bool) -> (u32, Vec<u8>) {
        let session = self.session.expect("a session");
        self.sequence += 1;
        let sequence = self.sequence;
        (OP_SEQUENCE, sequence_args(&session, sequence, cache))
    }

    /// Sends a COMPOUND of `ops`, after SEQUENCE once there is a session. Returns the COMPOUND's status and what the last operation answered
    /// after its status
    fn compound(&mut self, ops: &[(u32, Vec<u8>)]) -> (u32, Vec<u8>) {
        let mut all = Vec::new();
        if self.session.is_some() {
            all.push(self.sequence4(false));
        }
        all.extend_from_slice(ops);
        let results = self.compound_raw(1, &all);
        compound_result(&all, &results)
    }

    /// The handle the last of `ops` leaves current
    fn fh4(&mut self, ops: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut ops = ops.to_vec();
        ops.push((OP_GETFH, Vec::new()));
        let (status, body) = self.compound(&ops);
        assert_eq!(status, 0);
        Reader::new(&body).opaque().unwrap().to_vec()
    }

    /// EXCHANGE_ID and CREATE_SESSION, after which COMPOUNDs go in the session. Returns the
    /// client id
    fn session4(&mut self) -> u64 {
        let a = exchange_id4(b"test client", [1; 8]);
        let (status, body) = self.compound(&[(OP_EXCHANGE_ID, a)]);
        assert_eq!(status, 0);
        let mut r = Reader::new(&body);
        let clientid = r.u64().unwrap();
        let sequence = r.u32().unwrap();
        // Not pNFS, and not yet confirmed
        assert_eq!(r.u32(), Ok(0x0001_0000));
        let mut a = Vec::new();
        a.put_u64(clientid);
        a.put_u32(sequence);
        // CONN_BACK_CHAN and PERSIST
        a.put_u32(3);
        for attrs in [
            [0, 1 << 20, 1 << 20, 1 << 16, 32, 64],
            [0, 4096, 4096, 0, 2, 1],
        ] {
            for value in attrs {
                a.put_u32(value);
            }
            a.put_u32(0);
        }
        a.put_u32(0x4000_0000);
        // AUTH_NONE for callbacks
        a.put_u32(1);
        a.put_u32(0);
        let (status, body) = self.compound(&[(OP_CREATE_SESSION, a.clone())]);
        assert_eq!(status, 0);
        let mut r = Reader::new(&body);
        let session: [u8; 16] = r.fixed(16).unwrap().try_into().unwrap();
        assert_eq!(r.u32(), Ok(sequence));
        // Not persistent; the backchannel taken
        assert_eq!(r.u32(), Ok(2));
        // The fore channel: no padding, the sizes asked for, no more operations than 128 and
        // slots than 16
        let fore: Vec<u32> = (0..6).map(|_| r.u32().unwrap()).collect();
        assert_eq!(fore, [0, 1 << 20, 1 << 20, 1 << 16, 32, 16]);
        // A retransmitted CREATE_SESSION gets the same reply
        let (status, again) = self.compound(&[(OP_CREATE_SESSION, a)]);
        assert_eq!((status, &again), (0, &body));
        self.session = Some(session);
        self.sequence = 0;
        assert_eq!(
            self.compound(&[(OP_RECLAIM_COMPLETE, args(|a| a.put_bool(false)))])
                .0,
            0
        );
        clientid
    }
}

/// EXCHANGE_ID's arguments for a client `owner`, with SP4_NONE and an implementation id
fn exchange_id4(owner: &[u8], verifier: [u8; 8]) -> Vec<u8> {
    let mut a = Vec::new();
    a.put_fixed(&verifier);
    a.put_opaque(owner);
    a.put_u32(0);
    a.put_u32(0);
    a.put_u32(1);
    a.put_opaque(b"example.com");
    a.put_opaque(b"test");
    a.put_u64(0);
    a.put_u32(0);
    a
}

fn sequence_args(session: &[u8; 16], sequence: u32, cache: bool) -> Vec<u8> {
    let mut a = Vec::new();
    a.put_fixed(session);
    a.put_u32(sequence);
    // Slot 0, the highest in use
    a.put_u32(0);
    a.put_u32(0);
    a.put_bool(cache);
    a
}

/// The status of a COMPOUND's reply to `ops`, and what its last operation answered after its
/// status, checking that the others succeeded
fn compound_result(ops: &[(u32, Vec<u8>)], results: &[u8]) -> (u32, Vec<u8>) {
    let mut r = Reader::new(results);
    let status = r.u32().unwrap();
    assert_eq!(r.opaque(), Ok(&b"tag"[..]));
    let count = r.u32().unwrap();
    for i in 0..count {
        let op = r.u32().unwrap();
        let op_status = r.u32().unwrap();
        assert_eq!(op, ops[i as usize].0, "results of {ops:?}");
        if i + 1 == count {
            return (status, r.rest().to_vec());
        }
        assert_eq!(op_status, 0, "operation {op} failed");
        // The bodies of those that have one
        match op {
            OP_SEQUENCE => {
                r.fixed(16 + 20).unwrap();
            }
            OP_OPEN => {
                // stateid, change_info4, rflags, attrset and no delegation
                r.fixed(16 + 20 + 4).unwrap();
                for _ in 0..r.u32().unwrap() {
                    r.u32().unwrap();
                }
                r.u32().unwrap();
            }
            OP_READ => {
                r.bool().unwrap();
                r.opaque().unwrap();
            }
            _ => {}
        }
    }
    (status, Vec::new())
}

fn opaque4(data: &[u8]) -> Vec<u8> {
    args(|a| a.put_opaque(data))
}

/// A bitmap4 of `bits`
fn bits4(bits: &[u32]) -> Vec<u8> {
    let mut mask = [0u32; 2];
    for bit in bits {
        mask[(bit / 32) as usize] |= 1 << (bit % 32);
    }
    args(|a| {
        a.put_u32(2);
        a.put_u32(mask[0]);
        a.put_u32(mask[1]);
    })
}

/// An OPEN of `name` in `dir`, creating it UNCHECKED4 with mode 0640 if `create`. Returns
/// the status, the stateid and the result flags
fn open4(
    h: &mut Harness,
    dir: &[u8],
    clientid: u64,
    name: &str,
    access: u32,
    create: bool,
) -> (u32, Vec<u8>, u32) {
    let mut a = Vec::new();
    a.put_u32(0);
    a.put_u32(access);
    a.put_u32(0);
    a.put_u64(clientid);
    a.put_opaque(b"owner");
    a.put_u32(u32::from(create));
    if create {
        a.put_u32(0);
        a.extend_from_slice(&bits4(&[33]));
        a.put_opaque(&0o640u32.to_be_bytes());
    }
    // CLAIM_NULL
    a.put_u32(0);
    a.put_opaque(name.as_bytes());
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(dir)), (OP_OPEN, a)]);
    if status != 0 {
        return (status, Vec::new(), 0);
    }
    let mut r = Reader::new(&body);
    let stateid = r.fixed(16).unwrap().to_vec();
    // change_info4
    r.bool().unwrap();
    r.u64().unwrap();
    r.u64().unwrap();
    let rflags = r.u32().unwrap();
    (status, stateid, rflags)
}

/// A LOCKT of bytes 50..51 by `owner`
fn lockt4(file: &[u8], clientid: u64, owner: &[u8]) -> Ops {
    let mut a = Vec::new();
    // WRITE_LT
    a.put_u32(2);
    a.put_u64(50);
    a.put_u64(1);
    a.put_u64(clientid);
    a.put_opaque(owner);
    vec![(OP_PUTFH, opaque4(file)), (OP_LOCKT, a)]
}

#[test]
fn nfs4_mount_files_and_locks() {
    let mut h = start_version(false, true);
    let clientid = h.session4();
    // The export is the pseudo-root's one entry, by its secret name
    let export = h.nfs.v4().export_path();
    let name = export.trim_start_matches('/').to_owned();
    assert!(name.starts_with("export.") && name.len() > 20);
    let root = h.fh4(&[
        (OP_PUTROOTFH, Vec::new()),
        (OP_LOOKUP, opaque4(name.as_bytes())),
    ]);
    assert_eq!(handle(&mut Reader::new(&opaque4(&root))), ROOT);
    let (status, body) = h.compound(&[
        (OP_PUTFH, opaque4(&root)),
        (OP_GETATTR, bits4(&[1, 20, 33])),
    ]);
    assert_eq!(status, 0);
    let mut r = Reader::new(&body);
    // The attributes asked for come back, in order: type, fileid, mode
    assert_eq!(
        (r.u32(), r.u32(), r.u32()),
        (Ok(2), Ok((1 << 1) | (1 << 20)), Ok(1 << 1))
    );
    let values = r.opaque().unwrap().to_vec();
    let mut v = Reader::new(&values);
    assert_eq!(v.u32(), Ok(2));
    assert_eq!(v.u64(), Ok(1));
    assert_eq!(v.u32(), Ok(0o755));
    // Among the attributes supported, NFSv4.1's suppattr_exclcreat, in the third word
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&root)), (OP_GETATTR, bits4(&[0]))]);
    assert_eq!(status, 0);
    let mut r = Reader::new(&body);
    assert_eq!((r.u32(), r.u32(), r.u32()), (Ok(1), Ok(1), Ok(4 + 3 * 4)));
    assert_eq!(r.u32(), Ok(3));
    r.u32().unwrap();
    r.u32().unwrap();
    assert_eq!(r.u32(), Ok(1 << (75 - 64)));
    // LOOKUPP from the root leads back to the pseudo-root, which may be read and searched,
    // not changed
    let pseudo = h.fh4(&[(OP_PUTFH, opaque4(&root)), (OP_LOOKUPP, Vec::new())]);
    assert_eq!(&pseudo[..8], [0; 8]);
    let (status, body) = h.compound(&[
        (OP_PUTROOTFH, Vec::new()),
        (OP_ACCESS, args(|a| a.put_u32(0x3f))),
    ]);
    assert_eq!(
        (status, &body[..]),
        (0, &[0, 0, 0, 0x3f, 0, 0, 0, 0x23][..])
    );
    // NFSv3's MNT hands out nothing on a v4 server
    let results = h.call(MOUNT, 1, &args(|a| a.put_opaque(b"/export")));
    assert_eq!(results, 13u32.to_be_bytes());

    // An open that creates, written and read through its stateid, then closed. Only POSIX
    // locks are promised: no confirmation, as in NFSv4.0
    let (status, stateid, rflags) = open4(&mut h, &root, clientid, "file", 3, true);
    assert_eq!((status, rflags), (0, 4));
    let file = h.fh4(&[(OP_PUTFH, opaque4(&root)), (OP_LOOKUP, opaque4(b"file"))]);
    let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    let mut a = Vec::new();
    a.put_fixed(&stateid);
    a.put_u64(0);
    // UNSTABLE4
    a.put_u32(0);
    a.put_opaque(&data);
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_WRITE, a)]);
    assert_eq!(status, 0);
    assert_eq!(&body[..8], [0, 0, 0x27, 0x10, 0, 0, 0, 0]);
    // Split at the session's max_write
    assert_eq!(h.counters.largest_write.load(Ordering::SeqCst), 4096);
    let mut a = Vec::new();
    a.put_fixed(&stateid);
    a.put_u64(9000);
    a.put_u32(5000);
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_READ, a)]);
    assert_eq!(status, 0);
    let mut r = Reader::new(&body);
    assert_eq!(r.bool(), Ok(true));
    assert_eq!(r.opaque(), Ok(&data[9000..]));
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_GETATTR, bits4(&[33]))]);
    assert_eq!(status, 0);
    assert_eq!(&body[body.len() - 4..], 0o640u32.to_be_bytes());
    // A size set through the open is an ftruncate, which carries the open's handle; one with
    // the anonymous stateid is a truncate
    for (stateid, with_handle) in [(stateid.clone(), 1), (vec![0; 16], 1)] {
        let mut a = Vec::new();
        a.put_fixed(&stateid);
        a.extend_from_slice(&bits4(&[4]));
        a.put_opaque(&10_000u64.to_be_bytes());
        let ops = [(OP_PUTFH, opaque4(&file)), (OP_SETATTR, a)];
        assert_eq!(h.compound(&ops).0, 0);
        assert_eq!(
            h.counters.truncates_with_handle.load(Ordering::SeqCst),
            with_handle
        );
    }

    // Byte-range locks, kept here as the filesystem has none
    let mut a = Vec::new();
    // WRITE_LT, not a reclaim, bytes 0..100, by a new lock-owner of the open
    a.put_u32(2);
    a.put_bool(false);
    a.put_u64(0);
    a.put_u64(100);
    a.put_bool(true);
    a.put_u32(0);
    a.put_fixed(&stateid);
    a.put_u32(0);
    a.put_u64(clientid);
    a.put_opaque(b"locker");
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_LOCK, a)]);
    assert_eq!(status, 0);
    let lock = body[..16].to_vec();
    // NFS4ERR_DENIED for another owner, not for the one holding it
    assert_eq!(h.compound(&lockt4(&file, clientid, b"other")).0, 10010);
    assert_eq!(h.compound(&lockt4(&file, clientid, b"locker")).0, 0);
    let mut a = Vec::new();
    a.put_u32(2);
    a.put_u32(0);
    a.put_fixed(&lock);
    a.put_u64(0);
    a.put_u64(u64::MAX);
    assert_eq!(
        h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_LOCKU, a)]).0,
        0
    );
    assert_eq!(h.compound(&lockt4(&file, clientid, b"other")).0, 0);

    let mut a = Vec::new();
    a.put_u32(0);
    a.put_fixed(&stateid);
    assert_eq!(
        h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_CLOSE, a)]).0,
        0
    );
    // NFS4ERR_BAD_STATEID once closed
    let mut a = Vec::new();
    a.put_fixed(&stateid);
    a.put_u64(0);
    a.put_u32(1);
    assert_eq!(
        h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_READ, a)]).0,
        10025
    );
    // An open of the current file (CLAIM_FH), read and closed through the current stateid
    let mut a = Vec::new();
    a.put_u32(0);
    a.put_u32(1);
    a.put_u32(0);
    a.put_u64(clientid);
    a.put_opaque(b"owner");
    a.put_u32(0);
    a.put_u32(4);
    let mut read = Vec::new();
    read.put_fixed(&CURRENT_STATEID);
    read.put_u64(0);
    read.put_u32(3);
    let mut close = Vec::new();
    close.put_u32(0);
    close.put_fixed(&CURRENT_STATEID);
    let (status, body) = h.compound(&[
        (OP_PUTFH, opaque4(&file)),
        (OP_OPEN, a.clone()),
        (OP_READ, read),
        (OP_CLOSE, close.clone()),
    ]);
    // The invalid stateid once closed
    assert_eq!(
        (status, &body[..]),
        (0, &[&u32::MAX.to_be_bytes()[..], &[0; 12]].concat()[..])
    );
    // Without an operation before it to set one, the current stateid is NFS4ERR_BAD_STATEID
    let ops = [(OP_PUTFH, opaque4(&file)), (OP_CLOSE, close)];
    assert_eq!(h.compound(&ops).0, 10025);
    // TEST_STATEID knows an open's stateid, and FREE_STATEID leaves it to CLOSE
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_OPEN, a)]);
    assert_eq!(status, 0);
    let stateid = body[..16].to_vec();
    let mut test = Vec::new();
    test.put_u32(2);
    test.put_fixed(&stateid);
    test.put_fixed(&[9; 16]);
    let (status, body) = h.compound(&[(OP_TEST_STATEID, test)]);
    assert_eq!(status, 0);
    assert_eq!(body, [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0x27, 0x29]);
    let (status, _) = h.compound(&[(OP_FREE_STATEID, stateid.clone())]);
    assert_eq!(status, 10037);
    let mut a = Vec::new();
    a.put_u32(0);
    a.put_fixed(&stateid);
    assert_eq!(
        h.compound(&[(OP_PUTFH, opaque4(&file)), (OP_CLOSE, a)]).0,
        0
    );
    assert_eq!(open4(&mut h, &root, clientid, "missing", 1, false).0, 2);

    // A directory, listed, renamed and removed
    let mut a = Vec::new();
    a.put_u32(2);
    a.put_opaque(b"dir");
    a.extend_from_slice(&bits4(&[]));
    a.put_opaque(&[]);
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&root)), (OP_CREATE, a)]);
    // change_info4, and no attributes set
    assert_eq!((status, body.len()), (0, 20 + 4));
    let dir = h.fh4(&[(OP_PUTFH, opaque4(&root)), (OP_LOOKUP, opaque4(b"dir"))]);
    let parent = h.fh4(&[(OP_PUTFH, opaque4(&dir)), (OP_LOOKUPP, Vec::new())]);
    assert_eq!(parent, root);
    let mut a = Vec::new();
    a.put_u64(0);
    a.put_fixed(&[0; 8]);
    a.put_u32(1000);
    a.put_u32(8192);
    a.extend_from_slice(&bits4(&[1, 19]));
    let (status, body) = h.compound(&[(OP_PUTFH, opaque4(&root)), (OP_READDIR, a)]);
    assert_eq!(status, 0);
    let mut r = Reader::new(&body[8..]);
    let mut names = Vec::new();
    while r.bool().unwrap() {
        // Cookies 1 and 2 are reserved
        assert!(r.u64().unwrap() > 2);
        names.push(String::from_utf8(r.opaque().unwrap().to_vec()).unwrap());
        // The bitmap of type and filehandle, then their values
        let words = r.u32().unwrap();
        assert_eq!(words, 1);
        assert_eq!(r.u32(), Ok((1 << 1) | (1 << 19)));
        r.opaque().unwrap();
    }
    assert_eq!(r.bool(), Ok(true));
    assert_eq!(names, ["dir", "file"]);
    let rename = args(|a| {
        a.put_opaque(b"dir");
        a.put_opaque(b"moved");
    });
    let ops = [
        (OP_PUTFH, opaque4(&root)),
        (OP_SAVEFH, Vec::new()),
        (OP_PUTFH, opaque4(&root)),
        (OP_RENAME, rename),
    ];
    assert_eq!(h.compound(&ops).0, 0);
    let ops = [(OP_PUTFH, opaque4(&root)), (OP_REMOVE, opaque4(b"moved"))];
    assert_eq!(h.compound(&ops).0, 0);
    let ops = [(OP_PUTFH, opaque4(&root)), (OP_LOOKUP, opaque4(b"moved"))];
    assert_eq!(h.compound(&ops).0, 2);

    // NFSv4.0's RENEW is gone; ACCESS grants what is asked
    assert_eq!(
        h.compound(&[(OP_RENEW, args(|a| a.put_u64(clientid)))]).0,
        10004
    );
    let (status, body) = h.compound(&[
        (OP_PUTFH, opaque4(&root)),
        (OP_ACCESS, args(|a| a.put_u32(0x1f))),
    ]);
    assert_eq!(
        (status, &body[..]),
        (0, &[0, 0, 0, 0x1f, 0, 0, 0, 0x1f][..])
    );

    // Once a handle of the export has been used, the mount is made: the export can no longer
    // be looked up
    let ops = [
        (OP_PUTROOTFH, Vec::new()),
        (OP_LOOKUP, opaque4(name.as_bytes())),
    ];
    assert_eq!(h.compound(&ops).0, 2);
    // A handle with another key is NFS4ERR_BADHANDLE
    let mut forged = root.clone();
    forged[15] ^= 1;
    assert_eq!(h.compound(&[(OP_PUTFH, opaque4(&forged))]).0, 10001);
    h.finish();
}

#[test]
fn nfs4_errors() {
    let mut h = start_version(false, false);
    // Outside a session, only what sets one up, and alone
    assert_eq!(h.compound(&[(OP_PUTROOTFH, Vec::new())]).0, 10071);
    let ops = [
        (OP_DESTROY_SESSION, vec![0; 16]),
        (OP_PUTROOTFH, Vec::new()),
    ];
    assert_eq!(h.compound(&ops).0, 10081);
    // An operation that is not one: NFS4ERR_OP_ILLEGAL, with OP_ILLEGAL as its result
    let mut a = Vec::new();
    a.put_opaque(b"tag");
    a.put_u32(1);
    a.put_u32(1);
    a.put_u32(99);
    h.xid += 1;
    let reply = rpc::answer(&h.nfs, &call_message(h.xid, NFS, 4, 1, &a)).unwrap();
    let (_, results) = accepted(&reply, h.xid);
    let illegal = 10044u32.to_be_bytes();
    assert_eq!(&results[..4], illegal);
    assert_eq!(&results[results.len() - 8..], [illegal, illegal].concat());
    // Minor versions other than 1, NFSv4.0 included
    let results = h.compound_raw(0, &[]);
    assert_eq!(&results[..4], 10021u32.to_be_bytes());
    // Versions other than 3 and 4: PROG_MISMATCH, 3 to 4
    h.xid += 1;
    let reply = rpc::answer(&h.nfs, &call_message(h.xid, NFS, 5, 0, &[])).unwrap();
    let (stat, rest) = accepted(&reply, h.xid);
    assert_eq!((stat, &rest[..]), (2, &[0, 0, 0, 3, 0, 0, 0, 4][..]));

    // An NFSv3 mount's server takes no NFSv4 client: NFS4ERR_PERM
    let ops = [(OP_EXCHANGE_ID, exchange_id4(b"test client", [1; 8]))];
    assert_eq!(h.compound(&ops).0, 1);
    h.finish();

    let mut h = start_version(false, true);
    let clientid = h.session4();
    // Once the mount is made, the client it was made with is the only one: no other owner, nor
    // the same one claiming to have restarted, which would drop what it holds
    h.nfs.v4().seal();
    let ops = [(OP_EXCHANGE_ID, exchange_id4(b"another", [1; 8]))];
    assert_eq!(h.compound(&ops).0, 1);
    let ops = [(OP_EXCHANGE_ID, exchange_id4(b"test client", [2; 8]))];
    assert_eq!(h.compound(&ops).0, 1);
    let ops = [(OP_EXCHANGE_ID, exchange_id4(b"test client", [1; 8]))];
    let (status, body) = h.compound(&ops);
    assert_eq!((status, &body[..8]), (0, &clientid.to_be_bytes()[..]));
    // No current handle: NFS4ERR_NOFILEHANDLE
    assert_eq!(h.compound(&[(OP_GETFH, Vec::new())]).0, 10020);
    // SEQUENCE only first
    let session = h.session.unwrap();
    let ops = [(OP_SEQUENCE, sequence_args(&session, 1, false))];
    assert_eq!(h.compound(&ops).0, 10064);

    // A retransmission is answered from the slot, without running again
    let create = |name: &[u8]| {
        let mut a = Vec::new();
        a.put_u32(2);
        a.put_opaque(name);
        a.extend_from_slice(&bits4(&[]));
        a.put_opaque(&[]);
        a
    };
    let root = h.fh4(&[(OP_PUTROOTFH, Vec::new())]);
    let sequence = h.sequence4(true);
    let ops = [
        sequence,
        (OP_PUTFH, opaque4(&root)),
        (OP_CREATE, create(b"dir")),
    ];
    // The pseudo-root takes no directory
    let first = h.compound_raw(1, &ops);
    assert_eq!(compound_result(&ops, &first).0, 13);
    let again = h.compound_raw(1, &ops);
    assert_eq!(again, first);
    // A large reply not asked to be cached is not, and its retransmission is not run again
    let export_root = args(|a| put_handle(a, ROOT));
    let export_root = Reader::new(&export_root).opaque().unwrap().to_vec();
    let (status, stateid, _) = open4(&mut h, &export_root, clientid, "big", 3, true);
    assert_eq!(status, 0);
    let big = h.fh4(&[
        (OP_PUTFH, opaque4(&export_root)),
        (OP_LOOKUP, opaque4(b"big")),
    ]);
    // A stateid is for the file it was opened for
    let mut a = Vec::new();
    a.put_fixed(&stateid);
    a.put_u64(0);
    a.put_u32(1);
    let ops = [(OP_PUTFH, opaque4(&export_root)), (OP_READ, a)];
    assert_eq!(h.compound(&ops).0, 10025);
    let mut write = Vec::new();
    write.put_fixed(&stateid);
    write.put_u64(0);
    write.put_u32(2);
    write.put_opaque(&[7; 8192]);
    let mut read = Vec::new();
    read.put_fixed(&stateid);
    read.put_u64(0);
    read.put_u32(8192);
    let ops = [(OP_PUTFH, opaque4(&big)), (OP_WRITE, write)];
    assert_eq!(h.compound(&ops).0, 0);
    let sequence = h.sequence4(false);
    let ops = [sequence, (OP_PUTFH, opaque4(&big)), (OP_READ, read)];
    let (status, body) = compound_result(&ops, &h.compound_raw(1, &ops));
    assert_eq!((status, body.len()), (0, 8 + 8192));
    let results = h.compound_raw(1, &ops);
    assert_eq!(compound_result(&ops, &results).0, 10068);
    // Sequence ids out of order, slots and sessions that are not
    let ops = [(OP_SEQUENCE, sequence_args(&session, h.sequence + 5, false))];
    assert_eq!(compound_result(&ops, &h.compound_raw(1, &ops)).0, 10063);
    let ops = [(OP_SEQUENCE, sequence_args(&[7; 16], 1, false))];
    assert_eq!(compound_result(&ops, &h.compound_raw(1, &ops)).0, 10052);
    let mut slot = sequence_args(&session, 1, false);
    slot[20..24].copy_from_slice(&99u32.to_be_bytes());
    let ops = [(OP_SEQUENCE, slot)];
    assert_eq!(compound_result(&ops, &h.compound_raw(1, &ops)).0, 10053);

    // The client cannot go while its session is there; after DESTROY_SESSION it can
    let destroy = (OP_DESTROY_CLIENTID, args(|a| a.put_u64(clientid)));
    assert_eq!(h.compound(&[destroy.clone()]).0, 10074);
    h.session = None;
    assert_eq!(h.compound(&[(OP_DESTROY_SESSION, session.to_vec())]).0, 0);
    let ops = [(OP_SEQUENCE, sequence_args(&session, h.sequence + 1, false))];
    assert_eq!(compound_result(&ops, &h.compound_raw(1, &ops)).0, 10052);
    assert_eq!(h.compound(&[destroy.clone()]).0, 0);
    assert_eq!(h.compound(&[destroy]).0, 10022);
    h.finish();
}
