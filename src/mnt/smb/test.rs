//! The client against a real session, over the in-process transport: what the SMB backend
//! asks of a filesystem, without the SMB server

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use super::client::Client;
use super::client::PathError;
use super::client::SetAttr;
use super::crypto::hmac_sha256;
use super::ntlm;
use super::smb2;
use super::smb2::Share;
use super::transport::Transport;
use super::wire::Put;
use super::wire::from_utf16;
use super::wire::u16_at;
use super::wire::u32_at;
use super::wire::u64_at;
use super::wire::utf16;
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
use crate::dev_fuse::DevFuse;

/// Small, so that writes are split
const MAX_WRITE: u32 = 4096;

#[derive(Debug)]
struct Inode {
    attr: FileAttr,
    data: Vec<u8>,
    children: BTreeMap<OsString, u64>,
}

#[derive(Debug, Default)]
struct Tree {
    inodes: HashMap<u64, Inode>,
    next: u64,
    /// What WRITE requests carried, in order
    write_sizes: Vec<usize>,
}

impl Tree {
    fn new() -> Self {
        let mut tree = Tree {
            next: 2,
            ..Tree::default()
        };
        tree.inodes.insert(1, inode(1, FileType::Directory, 0o755));
        tree
    }

    fn add(&mut self, parent: u64, name: &OsStr, kind: FileType, perm: u16) -> &Inode {
        let ino = self.next;
        self.next += 1;
        self.inodes.insert(ino, inode(ino, kind, perm));
        self.inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(name.to_owned(), ino);
        &self.inodes[&ino]
    }

    fn child(&self, parent: INodeNo, name: &OsStr) -> Result<u64, Errno> {
        let dir = self.inodes.get(&parent.0).ok_or(Errno::ENOENT)?;
        if dir.attr.kind != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        dir.children.get(name).copied().ok_or(Errno::ENOENT)
    }
}

fn inode(ino: u64, kind: FileType, perm: u16) -> Inode {
    let time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    Inode {
        attr: FileAttr {
            ino: INodeNo(ino),
            size: 0,
            blocks: 0,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm,
            nlink: 1,
            uid: 501,
            gid: 20,
            rdev: 0,
            blksize: 512,
            flags: 0,
        },
        data: Vec::new(),
        children: BTreeMap::new(),
    }
}

/// A filesystem in memory, with the tests holding its tree too
struct MemFs {
    tree: Arc<Mutex<Tree>>,
    destroyed: Arc<AtomicBool>,
}

const TTL: Duration = Duration::ZERO;

impl Filesystem for MemFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        config.set_max_write(MAX_WRITE).unwrap();
        Ok(())
    }

    fn destroy(&self) {
        self.destroyed.store(true, Ordering::SeqCst);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let tree = self.tree.lock().unwrap();
        match tree.child(parent, name) {
            Ok(ino) => reply.entry(&TTL, &tree.inodes[&ino].attr, Generation(0)),
            Err(errno) => reply.error(errno),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.tree.lock().unwrap().inodes.get(&ino.0) {
            Some(inode) => reply.attr(&TTL, &inode.attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
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
        let mut tree = self.tree.lock().unwrap();
        let Some(inode) = tree.inodes.get_mut(&ino.0) else {
            return reply.error(Errno::ENOENT);
        };
        if size.is_some() && fh != Some(FileHandle(ino.0)) {
            // The client truncates through the handle it opened
            return reply.error(Errno::EBADF);
        }
        if let Some(size) = size {
            inode.data.resize(size as usize, 0);
            inode.attr.size = size;
        }
        if let Some(mode) = mode {
            inode.attr.perm = (mode & 0o7777) as u16;
        }
        let time = |t: TimeOrNow| match t {
            TimeOrNow::SpecificTime(t) => t,
            TimeOrNow::Now => SystemTime::now(),
        };
        if let Some(atime) = atime {
            inode.attr.atime = time(atime);
        }
        if let Some(mtime) = mtime {
            inode.attr.mtime = time(mtime);
        }
        reply.attr(&TTL, &inode.attr);
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
        let mut tree = self.tree.lock().unwrap();
        if tree.child(parent, name).is_ok() {
            return reply.error(Errno::EEXIST);
        }
        let inode = tree.add(parent.0, name, FileType::Directory, mode as u16);
        reply.entry(&TTL, &inode.attr, Generation(0));
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        _kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        let mut tree = self.tree.lock().unwrap();
        if tree.child(parent, name).is_ok() {
            return reply.error(Errno::EEXIST);
        }
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDWR);
        #[allow(clippy::unnecessary_cast)]
        let (format, regular) = (libc::S_IFMT as u32, libc::S_IFREG as u32);
        assert_eq!(mode & format, regular);
        let inode = tree.add(
            parent.0,
            name,
            FileType::RegularFile,
            (mode & 0o7777) as u16,
        );
        // The handle is the inode number, so that the tests can check it comes back
        let fh = FileHandle(inode.attr.ino.0);
        reply.created(&TTL, &inode.attr, Generation(0), fh, FopenFlags::empty());
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, _: bool, reply: ReplyOpen) {
        reply.opened(FileHandle(ino.0), FopenFlags::empty());
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
        assert_eq!(fh, FileHandle(ino.0));
        let tree = self.tree.lock().unwrap();
        let data = &tree.inodes[&ino.0].data;
        let start = (offset as usize).min(data.len());
        let end = (start + size as usize).min(data.len());
        reply.data(&data[start..end]);
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        assert_eq!(fh, FileHandle(ino.0));
        let mut tree = self.tree.lock().unwrap();
        tree.write_sizes.push(data.len());
        let inode = tree.inodes.get_mut(&ino.0).unwrap();
        let end = offset as usize + data.len();
        if inode.data.len() < end {
            inode.data.resize(end, 0);
        }
        inode.data[offset as usize..end].copy_from_slice(data);
        inode.attr.size = inode.data.len() as u64;
        reply.written(data.len() as u32);
    }

    fn flush(&self, _: &Request, _: INodeNo, _: FileHandle, _: LockOwner, reply: ReplyEmpty) {
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
        let tree = self.tree.lock().unwrap();
        let dir = &tree.inodes[&ino.0];
        let mut entries = vec![
            (ino.0, FileType::Directory, OsString::from(".")),
            (ino.0, FileType::Directory, OsString::from("..")),
        ];
        for (name, child) in &dir.children {
            entries.push((*child, tree.inodes[child].attr.kind, name.clone()));
        }
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(ino), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut tree = self.tree.lock().unwrap();
        match tree.child(parent, name) {
            Ok(ino) if tree.inodes[&ino].attr.kind == FileType::Directory => {
                reply.error(Errno::EISDIR);
            }
            Ok(ino) => {
                tree.inodes.remove(&ino);
                tree.inodes
                    .get_mut(&parent.0)
                    .unwrap()
                    .children
                    .remove(name);
                reply.ok();
            }
            Err(errno) => reply.error(errno),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut tree = self.tree.lock().unwrap();
        match tree.child(parent, name) {
            Ok(ino) if !tree.inodes[&ino].children.is_empty() => reply.error(Errno::ENOTEMPTY),
            Ok(ino) => {
                tree.inodes.remove(&ino);
                tree.inodes
                    .get_mut(&parent.0)
                    .unwrap()
                    .children
                    .remove(name);
                reply.ok();
            }
            Err(errno) => reply.error(errno),
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
        let mut tree = self.tree.lock().unwrap();
        let ino = match tree.child(parent, name) {
            Ok(ino) => ino,
            Err(errno) => return reply.error(errno),
        };
        tree.inodes
            .get_mut(&parent.0)
            .unwrap()
            .children
            .remove(name);
        let replaced = tree
            .inodes
            .get_mut(&newparent.0)
            .unwrap()
            .children
            .insert(newname.to_owned(), ino);
        if let Some(replaced) = replaced {
            tree.inodes.remove(&replaced);
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(1000, 600, 500, 100, 50, 4096, 255, 1024);
    }
}

/// A session serving `MemFs` on a thread, and a client connected to it
struct Harness {
    client: Arc<Client>,
    transport: Arc<Transport>,
    tree: Arc<Mutex<Tree>>,
    destroyed: Arc<AtomicBool>,
    session: JoinHandle<std::io::Result<()>>,
}

impl Harness {
    fn new() -> Self {
        let transport = Arc::new(Transport::new());
        // SAFETY: neither call has preconditions
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let client = Arc::new(Client::new(transport.clone(), uid, gid));
        // Queued before the session starts, as the SMB mount does
        let init = client.begin_init().unwrap();
        let tree = Arc::new(Mutex::new(Tree::new()));
        let destroyed = Arc::new(AtomicBool::new(false));
        let filesystem = MemFs {
            tree: tree.clone(),
            destroyed: destroyed.clone(),
        };
        let device = Arc::new(DevFuse::from_transport(transport.clone()).unwrap());
        let session = std::thread::spawn(move || {
            Session::from_device(filesystem, device, SessionACL::Owner, Config::default())?.run()
        });
        client.complete_init(init).unwrap();
        Harness {
            client,
            transport,
            tree,
            destroyed,
            session,
        }
    }

    /// End the connection, as an unmount does, and wait for the session to end
    fn close(self) {
        self.transport.close();
        self.session.join().unwrap().unwrap();
        assert!(self.destroyed.load(Ordering::SeqCst));
    }
}

#[test]
fn files_are_created_written_and_read() {
    let conn = Harness::new();
    let client = &conn.client;

    let dir = client.mkdir(INodeNo::ROOT, "dir", 0o755).unwrap();
    assert_eq!(dir.attr.kind, FileType::Directory);
    let (file, fh) = client
        .create(dir.id, "file.txt", 0o644, libc::O_RDWR)
        .unwrap();
    assert_eq!(fh, file.id.0);
    assert_eq!(file.attr.perm, 0o644);
    assert_eq!(
        client
            .create(dir.id, "file.txt", 0o644, libc::O_RDWR)
            .unwrap_err(),
        Errno::EEXIST
    );

    // Split into writes of at most the max_write INIT negotiated
    let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    assert_eq!(
        client.write(file.id, fh, 0, &data, libc::O_RDWR).unwrap(),
        10_000
    );
    assert_eq!(conn.tree.lock().unwrap().write_sizes, [4096, 4096, 1808]);
    assert_eq!(
        client.read(file.id, fh, 9_990, 100, libc::O_RDWR).unwrap(),
        &data[9_990..]
    );
    assert_eq!(client.getattr(file.id, Some(fh)).unwrap().size, 10_000);

    let time = UNIX_EPOCH + Duration::new(1_234_567_890, 500);
    let attr = client
        .setattr(
            file.id,
            Some(fh),
            &SetAttr {
                size: Some(5),
                mode: Some(0o600),
                mtime: Some(time),
                ..SetAttr::default()
            },
        )
        .unwrap();
    assert_eq!((attr.size, attr.perm, attr.mtime), (5, 0o600, time));
    client.flush(file.id, fh).unwrap();
    client.release(file.id, fh, libc::O_RDWR).unwrap();

    let fh = client.open(file.id, libc::O_RDONLY).unwrap();
    assert_eq!(
        client.read(file.id, fh, 0, 100, libc::O_RDONLY).unwrap(),
        &data[..5]
    );
    // MemFs does not implement fsync, which is then taken as done
    client.fsync(file.id, fh).unwrap();
    client.fsync(file.id, fh).unwrap();
    client.release(file.id, fh, libc::O_RDONLY).unwrap();

    let stat = client.statfs(INodeNo::ROOT).unwrap();
    assert_eq!(
        (
            stat.blocks,
            stat.bfree,
            stat.bavail,
            stat.bsize,
            stat.frsize
        ),
        (1000, 600, 500, 4096, 1024)
    );
    conn.close();
}

#[test]
fn paths_resolve_through_the_tree() {
    let conn = Harness::new();
    let client = &conn.client;
    let a = client.mkdir(INodeNo::ROOT, "a", 0o755).unwrap();
    let b = client.mkdir(a.id, "b", 0o755).unwrap();
    let (file, fh) = client.create(b.id, "f", 0o644, libc::O_RDWR).unwrap();
    client.release(file.id, fh, libc::O_RDWR).unwrap();

    assert_eq!(client.resolve(&[]).unwrap().id, INodeNo::ROOT);
    assert_eq!(client.resolve(&["a", "b", "f"]).unwrap().id, file.id);
    assert_eq!(client.resolve_dir(&["a", "b"]).unwrap(), b.id);
    // A missing last component, and a missing directory on the way
    assert_eq!(
        client.resolve(&["a", "b", "g"]).unwrap_err(),
        PathError::Last(Errno::ENOENT)
    );
    assert_eq!(
        client.resolve(&["a", "c", "f"]).unwrap_err(),
        PathError::Parent(Errno::ENOENT)
    );
    assert_eq!(
        client.resolve(&["a", "b", "f", "x"]).unwrap_err(),
        PathError::Parent(Errno::ENOTDIR)
    );

    let fh = client.opendir(b.id).unwrap();
    let names: Vec<_> = client
        .readdir(b.id, fh, 0, 4096)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(names, [".", "..", "f"]);
    assert!(client.readdir(b.id, fh, 3, 4096).unwrap().is_empty());
    client.releasedir(b.id, fh).unwrap();

    // A rename makes what was cached under the old name stale
    client
        .rename(INodeNo::ROOT, "a", INodeNo::ROOT, "z")
        .unwrap();
    client.forget_path(&["a"]);
    assert_eq!(
        client.resolve(&["a", "b", "f"]).unwrap_err(),
        PathError::Parent(Errno::ENOENT)
    );
    assert_eq!(client.resolve(&["z", "b", "f"]).unwrap().id, file.id);

    // Replaced by the filesystem itself: the cached directory is noticed to be stale, and
    // the path resolved again
    {
        let mut tree = conn.tree.lock().unwrap();
        let old = tree
            .inodes
            .get_mut(&1)
            .unwrap()
            .children
            .remove(OsStr::new("z"))
            .unwrap();
        let moved = tree.inodes.remove(&old).unwrap();
        let new = tree
            .add(1, OsStr::new("z"), FileType::Directory, 0o755)
            .attr
            .ino
            .0;
        tree.inodes.get_mut(&new).unwrap().children = moved.children;
    }
    assert_eq!(client.resolve(&["z", "b", "f"]).unwrap().id, file.id);

    assert_eq!(
        client.rmdir(INodeNo::ROOT, "z").unwrap_err(),
        Errno::ENOTEMPTY
    );
    client.unlink(b.id, "f").unwrap();
    assert_eq!(client.lookup(b.id, "f").unwrap_err(), Errno::ENOENT);
    assert_eq!(client.lookup(b.id, "a/b").unwrap_err(), Errno::EINVAL);
    conn.close();
}

#[test]
fn requests_fail_once_the_connection_ends() {
    let conn = Harness::new();
    conn.transport.close();
    assert_eq!(
        conn.client.getattr(INodeNo::ROOT, None).unwrap_err(),
        Errno::ENOTCONN
    );
    conn.session.join().unwrap().unwrap();
    assert!(conn.destroyed.load(Ordering::SeqCst));
}

/// What the SMB tests log on with
const PASSWORD: &str = "secret";
const NEGOTIATE: u16 = 0;
const SESSION_SETUP: u16 = 1;
const TREE_CONNECT: u16 = 3;
const CREATE: u16 = 5;
const CLOSE: u16 = 6;
const READ: u16 = 8;
const WRITE: u16 = 9;
const QUERY_DIRECTORY: u16 = 14;
const QUERY_INFO: u16 = 16;
const SET_INFO: u16 = 17;
const RELATED: u32 = 0x4;
const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const ACCESS_DENIED: u32 = 0xC000_0022;
// CreateDisposition
const OPEN: u32 = 1;
const CREATE_NEW: u32 = 2;
const OVERWRITE_IF: u32 = 5;
const GENERIC_ALL: u32 = 0x1000_0000;

fn share(harness: &Harness, read_only: bool) -> Share {
    Share {
        client: harness.client.clone(),
        name: "share".to_owned(),
        read_only,
        user: "fuser".to_owned(),
        nt_hash: ntlm::nt_hash(PASSWORD),
        guid: [7; 16],
    }
}

/// An SMB client, as far as the tests need one
struct Smb<'a> {
    conn: smb2::Connection<'a>,
    message_id: u64,
    session: u64,
    tree: u32,
    /// The session key, once logged on
    key: Option<[u8; 16]>,
}

/// One response of a reply: its status, header and body
struct Response {
    status: u32,
    header: Vec<u8>,
    body: Vec<u8>,
}

impl<'a> Smb<'a> {
    fn new(share: &'a Share) -> Self {
        Smb {
            conn: smb2::Connection::new(share),
            message_id: 0,
            session: 0,
            tree: 0,
            key: None,
        }
    }

    fn header(&mut self, command: u16, flags: u32) -> Vec<u8> {
        let mut h = b"\xfeSMB".to_vec();
        h.put_u16(64);
        h.put_u16(1);
        h.put_u32(0);
        h.put_u16(command);
        h.put_u16(32);
        h.put_u32(flags);
        h.put_u32(0);
        h.put_u64(self.message_id);
        self.message_id += 1;
        h.put_u32(0);
        h.put_u32(self.tree);
        h.put_u64(self.session);
        h.extend_from_slice(&[0; 16]);
        h
    }

    /// Sends requests as one compound, each but the first `related` if asked
    fn compound(&mut self, requests: &[(u16, Vec<u8>)], related: bool) -> Vec<Response> {
        let mut message = Vec::new();
        let mut previous: Option<usize> = None;
        for (i, (command, body)) in requests.iter().enumerate() {
            if let Some(previous) = previous {
                let start = message.len().next_multiple_of(8);
                message.resize(start, 0);
                message.set_u32(previous + 20, (start - previous) as u32);
            }
            previous = Some(message.len());
            let flags = if related && i > 0 { RELATED } else { 0 };
            let header = self.header(*command, flags);
            message.extend_from_slice(&header);
            message.extend_from_slice(body);
        }
        let reply = self.conn.answer(&message).unwrap();
        let mut responses = Vec::new();
        let mut at = 0;
        loop {
            let next = u32_at(&reply, at + 20).unwrap() as usize;
            let end = if next == 0 { reply.len() } else { at + next };
            responses.push(Response {
                status: u32_at(&reply, at + 8).unwrap(),
                header: reply[at..at + 64].to_vec(),
                body: reply[at + 64..end].to_vec(),
            });
            if next == 0 {
                break;
            }
            at += next;
        }
        assert_eq!(responses.len(), requests.len());
        responses
    }

    fn call(&mut self, command: u16, body: Vec<u8>) -> Response {
        self.compound(&[(command, body)], false).pop().unwrap()
    }

    /// NEGOTIATE, logon, and a connection to the share
    fn connect(&mut self, password: &str, signing: bool) -> u32 {
        let mut b = Vec::new();
        b.put_u16(36);
        b.put_u16(3);
        // SecurityMode: signing enabled, and required if asked
        b.put_u16(if signing { 3 } else { 1 });
        b.put_u16(0);
        b.put_u32(0);
        b.extend_from_slice(&[0; 16 + 8]);
        for dialect in [0x0202u16, 0x0210, 0x0311] {
            b.put_u16(dialect);
        }
        let negotiated = self.call(NEGOTIATE, b);
        assert_eq!(negotiated.status, 0);
        assert_eq!(u16_at(&negotiated.body, 4), Some(0x0210));

        let flags = 0x1 | 0x10 | 0x8_0000 | 0x4000_0000;
        let negotiate = ntlm::client::negotiate(flags);
        let first = self.call(
            SESSION_SETUP,
            setup(&ntlm::client::neg_token_init(&negotiate)),
        );
        assert_eq!(first.status, MORE_PROCESSING_REQUIRED);
        self.session = u64_at(&first.header, 40).unwrap();
        let token = &first.body[8..];
        let challenge = ntlm::client::response_token(token).unwrap();
        let (auth, key) = ntlm::client::authenticate(&challenge, "fuser", password, flags);
        let second = self.call(
            SESSION_SETUP,
            setup(&ntlm::client::neg_token_resp_token(&auth)),
        );
        if second.status != 0 {
            return second.status;
        }
        self.key = Some(key);

        let path = utf16("\\\\127.0.0.1\\share");
        let mut b = Vec::new();
        b.put_u16(9);
        b.put_u16(0);
        b.put_u16(64 + 8);
        b.put_u16(path.len() as u16);
        b.extend_from_slice(&path);
        let connected = self.call(TREE_CONNECT, b);
        assert_eq!(connected.status, 0);
        self.tree = u32_at(&connected.header, 36).unwrap();
        0
    }
}

fn setup(token: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(25);
    b.put_u8(0);
    b.put_u8(1);
    b.put_u32(0);
    b.put_u32(0);
    b.put_u16(64 + 24);
    b.put_u16(token.len() as u16);
    b.put_u64(0);
    b.extend_from_slice(token);
    b
}

fn create(name: &str, disposition: u32, directory: bool) -> Vec<u8> {
    let name = utf16(name);
    let mut b = Vec::new();
    b.put_u16(57);
    b.put_u16(0);
    b.put_u32(2);
    b.extend_from_slice(&[0; 16]);
    b.put_u32(GENERIC_ALL);
    b.put_u32(0);
    b.put_u32(7);
    b.put_u32(disposition);
    b.put_u32(u32::from(directory));
    b.put_u16(64 + 56);
    b.put_u16(name.len() as u16);
    b.put_u64(0);
    b.extend_from_slice(&name);
    b
}

/// A FileId, or the one a related compound's CREATE made
fn put_fid(b: &mut Vec<u8>, fid: Option<u64>) {
    match fid {
        Some(fid) => {
            b.put_u64(fid);
            b.put_u64(fid);
        }
        None => b.extend_from_slice(&[0xff; 16]),
    }
}

fn close(fid: Option<u64>) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(24);
    // POSTQUERY_ATTRIB
    b.put_u16(1);
    b.put_u32(0);
    put_fid(&mut b, fid);
    b
}

fn query_info(fid: Option<u64>, info_type: u8, class: u8) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(41);
    b.put_u8(info_type);
    b.put_u8(class);
    b.put_u32(65536);
    b.extend_from_slice(&[0; 16]);
    put_fid(&mut b, fid);
    b
}

fn set_info(fid: u64, class: u8, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.put_u16(33);
    b.put_u8(1);
    b.put_u8(class);
    b.put_u32(data.len() as u32);
    b.put_u16(64 + 32);
    b.put_u16(0);
    b.put_u32(0);
    put_fid(&mut b, Some(fid));
    b.extend_from_slice(data);
    b
}

fn file_id(created: &Response) -> u64 {
    u64_at(&created.body, 64).unwrap()
}

#[test]
fn smb_logon_and_files() {
    let harness = Harness::new();
    let share = share(&harness, false);
    let mut smb = Smb::new(&share);
    assert_eq!(Smb::new(&share).connect("wrong", false), 0xC000_006D);
    assert_eq!(smb.connect(PASSWORD, false), 0);

    // A directory, and a file in it, written past one FUSE max_write and read back
    let dir = smb.call(CREATE, create("dir", CREATE_NEW, true));
    assert_eq!((dir.status, u32_at(&dir.body, 4)), (0, Some(2)));
    let dir = file_id(&dir);
    let file = smb.call(CREATE, create("dir\\file.txt", OVERWRITE_IF, false));
    assert_eq!(file.status, 0);
    let file = file_id(&file);
    let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    let mut b = Vec::new();
    b.put_u16(49);
    b.put_u16(64 + 48);
    b.put_u32(data.len() as u32);
    b.put_u64(0);
    put_fid(&mut b, Some(file));
    b.extend_from_slice(&[0; 16]);
    b.extend_from_slice(&data);
    let written = smb.call(WRITE, b);
    assert_eq!(
        (written.status, u32_at(&written.body, 4)),
        (0, Some(10_000))
    );
    let mut b = Vec::new();
    b.put_u16(49);
    b.put_u16(0);
    b.put_u32(20_000);
    b.put_u64(1000);
    put_fid(&mut b, Some(file));
    b.extend_from_slice(&[0; 17]);
    let read = smb.call(READ, b);
    assert_eq!(read.status, 0);
    assert_eq!(&read.body[16..], &data[1000..]);
    // FileStandardInformation: the end of file
    let info = smb.call(QUERY_INFO, query_info(Some(file), 1, 5));
    assert_eq!(u64_at(&info.body, 8 + 8), Some(10_000));
    assert_eq!(
        smb.call(CREATE, create("dir\\file.txt", CREATE_NEW, false))
            .status,
        OBJECT_NAME_COLLISION
    );

    // Renamed, then listed
    let target = utf16("dir\\renamed.txt");
    let mut rename = vec![0; 20];
    rename.set_u32(16, target.len() as u32);
    rename.extend_from_slice(&target);
    assert_eq!(smb.call(SET_INFO, set_info(file, 10, &rename)).status, 0);
    let pattern = utf16("*");
    let mut b = Vec::new();
    b.put_u16(33);
    // FileIdBothDirectoryInformation, restarting the scan
    b.put_u8(37);
    b.put_u8(1);
    b.put_u32(0);
    put_fid(&mut b, Some(dir));
    b.put_u16(64 + 32);
    b.put_u16(pattern.len() as u16);
    b.put_u32(65536);
    b.extend_from_slice(&pattern);
    let listed = smb.call(QUERY_DIRECTORY, b.clone());
    assert_eq!(listed.status, 0);
    let entries = &listed.body[8..];
    let mut names = Vec::new();
    let mut at = 0;
    loop {
        let len = u32_at(entries, at + 60).unwrap() as usize;
        names.push(from_utf16(&entries[at + 104..at + 104 + len]).unwrap());
        match u32_at(entries, at).unwrap() {
            0 => break,
            next => at += next as usize,
        }
    }
    assert_eq!(names, [".", "..", "renamed.txt"]);
    b[3] = 0;
    // STATUS_NO_MORE_FILES
    assert_eq!(smb.call(QUERY_DIRECTORY, b).status, 0x8000_0006);

    // Deleted on close: a disposition, then a compound that opens, stats and closes
    assert_eq!(smb.call(SET_INFO, set_info(file, 13, &[1])).status, 0);
    let closed = smb.call(CLOSE, close(Some(file)));
    assert_eq!((closed.status, u64_at(&closed.body, 48)), (0, Some(10_000)));
    let chain = smb.compound(
        &[
            (CREATE, create("dir\\renamed.txt", OPEN, false)),
            (QUERY_INFO, query_info(None, 1, 5)),
            (CLOSE, close(None)),
        ],
        true,
    );
    assert!(chain.iter().all(|r| r.status == OBJECT_NAME_NOT_FOUND));
    let chain = smb.compound(
        &[
            (CREATE, create("", OPEN, true)),
            (QUERY_INFO, query_info(None, 2, 5)),
            (CLOSE, close(None)),
        ],
        true,
    );
    assert!(chain.iter().all(|r| r.status == 0));
    // FileFsAttributeInformation: case-sensitive and case-preserving, Unicode names
    assert_eq!(u32_at(&chain[1].body, 8), Some(0x7));
    assert_eq!(smb.call(CLOSE, close(Some(dir))).status, 0);
}

#[test]
fn smb_signing() {
    let harness = Harness::new();
    let share = share(&harness, false);
    let mut smb = Smb::new(&share);
    assert_eq!(smb.connect(PASSWORD, true), 0);
    let key = smb.key.unwrap();
    let reply = smb.call(CREATE, create("", OPEN, true));
    assert_eq!(reply.status, 0);
    let mut response = [reply.header, reply.body].concat();
    // SMB2_FLAGS_SIGNED
    assert_ne!(u32_at(&response, 16).unwrap() & 0x8, 0);
    let signature = response[48..64].to_vec();
    response[48..64].fill(0);
    assert_eq!(&hmac_sha256(&key, &[&response])[..16], &signature[..]);
}

#[test]
fn smb_read_only_and_smb1() {
    let harness = Harness::new();
    let share = share(&harness, true);
    let mut smb = Smb::new(&share);
    assert_eq!(smb.connect(PASSWORD, false), 0);
    assert_eq!(
        smb.call(CREATE, create("new", CREATE_NEW, false)).status,
        ACCESS_DENIED
    );
    // A multi-protocol SMB 1 NEGOTIATE is answered in SMB 2, with the wildcard dialect
    let mut smb1 = b"\xffSMB\x72".to_vec();
    smb1.extend_from_slice(&[0; 27]);
    smb1.extend_from_slice(b"\x02NT LM 0.12\0\x02SMB 2.002\0\x02SMB 2.???\0");
    let reply = smb2::Connection::new(&share).answer(&smb1).unwrap();
    assert!(reply.starts_with(b"\xfeSMB"));
    assert_eq!(u16_at(&reply, 64 + 4), Some(0x02FF));
}
