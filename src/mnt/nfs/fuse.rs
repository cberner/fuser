//! The FUSE side of the NFS server: what the FUSE kernel module would send the session.
//!
//! Requests are queued on a [`Transport`] and their replies awaited, blocking the calling
//! thread. Node ids are never forgotten: NFS has no counterpart to `FUSE_FORGET`, and a
//! forgotten id could be given to a new file that old handles would then name.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use parking_lot::Condvar;
use parking_lot::Mutex;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

use super::transport::Caller;
use super::transport::Transport;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi::FUSE_KERNEL_MINOR_VERSION;
use crate::ll::fuse_abi::FUSE_KERNEL_VERSION;
use crate::ll::fuse_abi::fuse_access_in;
use crate::ll::fuse_abi::fuse_attr;
use crate::ll::fuse_abi::fuse_attr_out;
use crate::ll::fuse_abi::fuse_create_in;
use crate::ll::fuse_abi::fuse_dirent;
use crate::ll::fuse_abi::fuse_entry_out;
use crate::ll::fuse_abi::fuse_file_lock;
use crate::ll::fuse_abi::fuse_flush_in;
use crate::ll::fuse_abi::fuse_fsync_in;
use crate::ll::fuse_abi::fuse_getattr_in;
use crate::ll::fuse_abi::fuse_init_in;
use crate::ll::fuse_abi::fuse_kstatfs;
use crate::ll::fuse_abi::fuse_lk_in;
use crate::ll::fuse_abi::fuse_lk_out;
use crate::ll::fuse_abi::fuse_mknod_in;
use crate::ll::fuse_abi::fuse_opcode;
use crate::ll::fuse_abi::fuse_open_in;
use crate::ll::fuse_abi::fuse_open_out;
use crate::ll::fuse_abi::fuse_out_header;
use crate::ll::fuse_abi::fuse_read_in;
use crate::ll::fuse_abi::fuse_release_in;
use crate::ll::fuse_abi::fuse_setattr_in;
use crate::ll::fuse_abi::fuse_statfs_out;
use crate::ll::fuse_abi::fuse_write_in;
use crate::ll::fuse_abi::fuse_write_out;

/// FUSE's node id of the root
pub(crate) const ROOT: u64 = 1;
/// The largest read sent as one FUSE request, as Linux's default `max_pages` allows
pub(crate) const MAX_READ: u32 = 128 * 1024;
/// How much of a directory one `FUSE_READDIR` asks for
pub(crate) const READDIR_SIZE: u32 = 64 * 1024;
/// How long an open file handle is kept for further reads and writes once unused
#[cfg_attr(not(fuser_mount_impl = "nfs"), allow(dead_code))]
pub(crate) const HANDLE_IDLE: Duration = Duration::from_secs(2);

pub(crate) const S_IFMT: u32 = 0o170000;
pub(crate) const S_IFDIR: u32 = 0o040000;
pub(crate) const S_IFREG: u32 = 0o100000;

thread_local! {
    /// Whom the NFS call being answered on this thread was made by
    static CALLER: Cell<Option<Caller>> = const { Cell::new(None) };
}

/// Runs `answer` with the FUSE requests it makes carrying `caller`, from the call's AUTH_SYS
/// credentials. Requests made outside any call, and calls without credentials, carry the
/// mounting user
pub(crate) fn as_caller<T>(caller: Option<Caller>, answer: impl FnOnce() -> T) -> T {
    let previous = CALLER.replace(caller);
    let result = answer();
    CALLER.set(previous);
    result
}

/// A FUSE error: the errno the filesystem replied with
pub(crate) type FuseResult<T> = Result<T, i32>;

/// An open FUSE file handle, kept so that the reads and writes of one file do not each open
/// and release it
#[derive(Debug, Clone, Copy)]
struct Handle {
    /// Unique among the handles kept, as `fh` need not be: a filesystem may answer every open
    /// with the same one
    id: u64,
    fh: u64,
    /// The uid and gid it was opened as: only their calls use it
    owner: (u32, u32),
    /// The flags it was opened with
    flags: i32,
    readable: bool,
    writable: bool,
    /// Reads and writes using it right now
    users: u32,
    last_used: Instant,
}

#[derive(Debug)]
struct Inner {
    transport: Arc<Transport>,
    caller: Caller,
    /// The largest write to send as one request, once INIT has been answered
    max_write: Mutex<Option<u32>>,
    initialized: Condvar,
    /// Open file handles by node id
    handles: Mutex<HashMap<u64, Vec<Handle>>>,
    /// The parent of each directory looked up, for "..", which FUSE filesystems need not answer
    parents: Mutex<HashMap<u64, u64>>,
    /// The filesystem answered FSYNC with ENOSYS, so it is not sent again, as the kernel does
    no_fsync: AtomicBool,
    /// The same for ACCESS
    no_access: AtomicBool,
    /// The id of the last handle kept
    next_handle: AtomicU64,
}

/// A directory entry, and the cookie that resumes the listing after it
#[derive(Debug)]
pub(crate) struct DirEntry {
    pub(crate) name: Vec<u8>,
    pub(crate) ino: u64,
    pub(crate) cookie: u64,
}

/// The FUSE "kernel" side of a session
#[derive(Debug, Clone)]
pub(crate) struct Fuse(Arc<Inner>);

impl Fuse {
    pub(crate) fn new(transport: Arc<Transport>, caller: Caller) -> Self {
        Self(Arc::new(Inner {
            transport,
            caller,
            max_write: Mutex::new(None),
            initialized: Condvar::new(),
            handles: Mutex::default(),
            parents: Mutex::default(),
            no_fsync: AtomicBool::new(false),
            no_access: AtomicBool::new(false),
            next_handle: AtomicU64::new(0),
        }))
    }

    /// Queues `FUSE_INIT`, which must be the first request. `finish_init` takes the reply
    pub(crate) fn start_init(&self) -> FuseResult<mpsc::Receiver<Vec<u8>>> {
        // Not FUSE_RENAME_SWAP, so renames use the plain layout
        let (flags, flags2) = InitFlags::FUSE_BIG_WRITES.pair();
        let arg = fuse_init_in {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: super::nfs3::MAX_IO,
            flags,
            flags2,
            unused: [0; 11],
        };
        self.0
            .transport
            .submit(fuse_opcode::FUSE_INIT, 0, self.0.caller, &[arg.as_bytes()])
            .map_err(|e| e as i32)
    }

    /// Waits for the session to answer `FUSE_INIT`, after which writes can be sized
    pub(crate) fn finish_init(&self, reply: &mpsc::Receiver<Vec<u8>>) -> FuseResult<()> {
        let reply = reply.recv().map_err(|_| libc::ENOTCONN)?;
        let body = parse_reply(&reply)?;
        // fuse_init_out's max_write, at the same offset in every layout since ABI 7.5
        let max_write = body
            .get(20..24)
            .map(|b| u32::from_ne_bytes(b.try_into().expect("4 bytes")))
            .unwrap_or(4096)
            .clamp(4096, super::nfs3::MAX_IO);
        *self.0.max_write.lock() = Some(max_write);
        self.0.initialized.notify_all();
        log::debug!("FUSE session initialized, writing up to {max_write} bytes per request");
        Ok(())
    }

    fn max_write(&self) -> FuseResult<u32> {
        let mut max_write = self.0.max_write.lock();
        loop {
            if let Some(max_write) = *max_write {
                return Ok(max_write);
            }
            if self.0.transport.is_closed() {
                return Err(libc::ENOTCONN);
            }
            self.0
                .initialized
                .wait_for(&mut max_write, Duration::from_millis(100));
        }
    }

    /// Sends one request and waits for its reply, returning what follows `fuse_out_header`
    pub(crate) fn call(
        &self,
        opcode: fuse_opcode,
        nodeid: u64,
        args: &[&[u8]],
    ) -> FuseResult<Vec<u8>> {
        let receiver = self
            .0
            .transport
            .submit(opcode, nodeid, self.caller(), args)
            .map_err(|e| e as i32)?;
        // Dropped without a reply once the connection has closed
        let reply = receiver.recv().map_err(|_| libc::EIO)?;
        parse_reply(&reply).map(<[u8]>::to_vec)
    }

    fn caller(&self) -> Caller {
        CALLER.get().unwrap_or(self.0.caller)
    }

    fn owner(&self) -> (u32, u32) {
        let caller = self.caller();
        (caller.uid, caller.gid)
    }

    /// Which of the NFS ACCESS bits `asked` (READ 0x1, LOOKUP 0x2, MODIFY 0x4, EXTEND 0x8,
    /// DELETE 0x10 and EXECUTE 0x20, the same in NFSv3 and NFSv4) the filesystem grants the
    /// caller, through FUSE_ACCESS. Clients check these before operations they send no request
    /// for, such as opening a file. A filesystem without ACCESS grants them all, and is not
    /// asked again, as the kernel does.
    ///
    /// DELETE is always granted. macOS asks it of the node to be removed or renamed, which
    /// only its directory (and that directory's sticky bit) decides, and this server does not
    /// know which directory is meant. The REMOVE or RENAME that follows is the filesystem's to
    /// refuse
    pub(crate) fn granted_access(&self, nodeid: u64, asked: u32) -> FuseResult<u32> {
        let mut granted = asked & 0x10;
        for (bits, mask) in [
            (0x1, libc::R_OK),
            (0x2 | 0x20, libc::X_OK),
            (0x4 | 0x8, libc::W_OK),
        ] {
            let wanted = asked & bits;
            if wanted == 0 {
                continue;
            }
            if self.0.no_access.load(Ordering::Relaxed) {
                granted |= wanted;
                continue;
            }
            let arg = fuse_access_in { mask, padding: 0 };
            match self.call(fuse_opcode::FUSE_ACCESS, nodeid, &[arg.as_bytes()]) {
                Ok(_) => granted |= wanted,
                Err(libc::EACCES | libc::EPERM | libc::EROFS) => {}
                Err(libc::ENOSYS) => {
                    self.0.no_access.store(true, Ordering::Relaxed);
                    granted |= wanted;
                }
                Err(errno) => return Err(errno),
            }
        }
        Ok(granted)
    }

    /// Queues a request whose reply does not matter
    fn post(&self, opcode: fuse_opcode, nodeid: u64, args: &[&[u8]]) {
        let _ = self.0.transport.submit(opcode, nodeid, self.caller(), args);
    }

    /// Sends a request that creates a node in `dir`, recording a new directory's parent
    pub(crate) fn make(
        &self,
        opcode: fuse_opcode,
        dir: u64,
        args: &[&[u8]],
    ) -> FuseResult<fuse_entry_out> {
        let entry: fuse_entry_out = decode(&self.call(opcode, dir, args)?)?;
        if entry.attr.mode & S_IFMT == S_IFDIR {
            self.0.parents.lock().insert(entry.nodeid, dir);
        }
        Ok(entry)
    }

    pub(crate) fn lookup(&self, dir: u64, name: &[u8]) -> FuseResult<fuse_entry_out> {
        let entry = self.make(fuse_opcode::FUSE_LOOKUP, dir, &[name, b"\0"])?;
        // A node id of 0 is a negative entry
        if entry.nodeid == 0 {
            return Err(libc::ENOENT);
        }
        Ok(entry)
    }

    /// Resolves a name, including "." and "..", to a node id
    pub(crate) fn resolve(&self, dir: u64, name: &[u8]) -> FuseResult<u64> {
        match name {
            b"." => return Ok(dir),
            b".." if dir == ROOT => return Ok(ROOT),
            b".." => {
                if let Some(&parent) = self.0.parents.lock().get(&dir) {
                    return Ok(parent);
                }
            }
            _ => {}
        }
        Ok(self.lookup(dir, name)?.nodeid)
    }

    pub(crate) fn getattr(&self, nodeid: u64) -> FuseResult<fuse_attr> {
        let arg = fuse_getattr_in::new_zeroed();
        let out: fuse_attr_out =
            decode(&self.call(fuse_opcode::FUSE_GETATTR, nodeid, &[arg.as_bytes()])?)?;
        Ok(out.attr)
    }

    pub(crate) fn setattr(&self, nodeid: u64, arg: &fuse_setattr_in) -> FuseResult<fuse_attr> {
        let out: fuse_attr_out =
            decode(&self.call(fuse_opcode::FUSE_SETATTR, nodeid, &[arg.as_bytes()])?)?;
        Ok(out.attr)
    }

    pub(crate) fn statfs(&self, nodeid: u64) -> FuseResult<fuse_kstatfs> {
        let out: fuse_statfs_out = decode(&self.call(fuse_opcode::FUSE_STATFS, nodeid, &[])?)?;
        Ok(out.st)
    }

    fn open(&self, nodeid: u64, opcode: fuse_opcode, flags: i32) -> FuseResult<u64> {
        let arg = fuse_open_in {
            flags,
            open_flags: 0,
        };
        let out: fuse_open_out = decode(&self.call(opcode, nodeid, &[arg.as_bytes()])?)?;
        Ok(out.fh)
    }

    /// Flushes and releases a file handle, as closing its last descriptor would
    fn release_file(&self, nodeid: u64, handle: &Handle) {
        if handle.writable {
            let mut flush = fuse_flush_in::new_zeroed();
            flush.fh = handle.fh;
            self.post(fuse_opcode::FUSE_FLUSH, nodeid, &[flush.as_bytes()]);
        }
        let mut release = fuse_release_in::new_zeroed();
        release.fh = handle.fh;
        release.flags = handle.flags;
        self.post(fuse_opcode::FUSE_RELEASE, nodeid, &[release.as_bytes()]);
    }

    /// A file handle that can read, or write, the node: one kept from earlier, or a new one
    fn acquire(&self, nodeid: u64, write: bool) -> FuseResult<HandleGuard> {
        {
            let mut handles = self.0.handles.lock();
            let owner = self.owner();
            if let Some(handle) = handles.get_mut(&nodeid).and_then(|hs| {
                hs.iter_mut()
                    .find(|h| h.owner == owner && if write { h.writable } else { h.readable })
            }) {
                handle.users += 1;
                handle.last_used = Instant::now();
                return Ok(HandleGuard {
                    fuse: self.clone(),
                    nodeid,
                    id: handle.id,
                    fh: handle.fh,
                    flags: handle.flags,
                });
            }
        }
        let flags = if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        let fh = self.open(nodeid, fuse_opcode::FUSE_OPEN, flags)?;
        let id = self.keep(nodeid, fh, flags, 1);
        Ok(HandleGuard {
            fuse: self.clone(),
            nodeid,
            id,
            fh,
            flags,
        })
    }

    /// Keeps a handle for later reads and writes, returning its id
    fn keep(&self, nodeid: u64, fh: u64, flags: i32, users: u32) -> u64 {
        let access = flags & libc::O_ACCMODE;
        let id = self.0.next_handle.fetch_add(1, Ordering::Relaxed) + 1;
        self.0
            .handles
            .lock()
            .entry(nodeid)
            .or_default()
            .push(Handle {
                id,
                fh,
                owner: self.owner(),
                flags,
                readable: access != libc::O_WRONLY,
                writable: access != libc::O_RDONLY,
                users,
                last_used: Instant::now(),
            });
        id
    }

    /// Releases the file handles unused for `idle`
    pub(crate) fn release_idle(&self, idle: Duration) {
        let mut released = Vec::new();
        self.0.handles.lock().retain(|&nodeid, hs| {
            hs.retain(|h| {
                let keep = h.users > 0 || h.last_used.elapsed() < idle;
                if !keep {
                    released.push((nodeid, *h));
                }
                keep
            });
            !hs.is_empty()
        });
        for (nodeid, handle) in released {
            self.release_file(nodeid, &handle);
        }
    }

    /// Runs `release_idle` periodically, until the connection closes
    #[cfg_attr(not(fuser_mount_impl = "nfs"), allow(dead_code))]
    pub(crate) fn release_idle_forever(&self) {
        while !self.0.transport.is_closed() {
            std::thread::sleep(HANDLE_IDLE / 2);
            self.release_idle(HANDLE_IDLE);
        }
    }

    /// Releases every file handle, as closing every descriptor would, and asks the session to
    /// end with `FUSE_DESTROY`, after which the connection is closed. Nothing waits for the
    /// replies: the session may not be running
    pub(crate) fn shutdown(&self) {
        if self.0.transport.is_closed() {
            return;
        }
        let handles = std::mem::take(&mut *self.0.handles.lock());
        for (nodeid, hs) in handles {
            for handle in hs {
                self.release_file(nodeid, &handle);
            }
        }
        self.post(fuse_opcode::FUSE_DESTROY, 0, &[]);
        self.0.transport.close();
    }

    /// Opens a file for an open the client keeps, rather than one kept here
    pub(crate) fn open_file(&self, nodeid: u64, flags: i32) -> FuseResult<u64> {
        self.open(nodeid, fuse_opcode::FUSE_OPEN, flags)
    }

    /// Flushes and releases what `open_file` or `create_open` opened
    /// Closes a file handle as close(2) does, returning what the flush of a writable one
    /// answered, which is how a filesystem reports a write it could not complete
    pub(crate) fn close_file_checked(&self, nodeid: u64, fh: u64, flags: i32) -> FuseResult<()> {
        let flushed = if flags & libc::O_ACCMODE == libc::O_RDONLY {
            Ok(())
        } else {
            let mut flush = fuse_flush_in::new_zeroed();
            flush.fh = fh;
            match self.call(fuse_opcode::FUSE_FLUSH, nodeid, &[flush.as_bytes()]) {
                Ok(_) | Err(libc::ENOSYS) => Ok(()),
                Err(errno) => Err(errno),
            }
        };
        let mut release = fuse_release_in::new_zeroed();
        release.fh = fh;
        release.flags = flags;
        self.post(fuse_opcode::FUSE_RELEASE, nodeid, &[release.as_bytes()]);
        flushed
    }

    pub(crate) fn close_file(&self, nodeid: u64, fh: u64, flags: i32) {
        let access = flags & libc::O_ACCMODE;
        self.release_file(
            nodeid,
            &Handle {
                id: 0,
                fh,
                owner: self.owner(),
                flags,
                readable: access != libc::O_WRONLY,
                writable: access != libc::O_RDONLY,
                users: 0,
                last_used: Instant::now(),
            },
        );
    }

    /// Takes or drops (`typ` F_UNLCK) a POSIX lock on `start..=end`, without waiting
    pub(crate) fn setlk(
        &self,
        nodeid: u64,
        fh: u64,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
    ) -> FuseResult<()> {
        let arg = lk_in(fh, owner, start, end, typ);
        self.call(fuse_opcode::FUSE_SETLK, nodeid, &[arg.as_bytes()])
            .map(drop)
    }

    /// The lock that would conflict with `typ` on `start..=end`; its type is F_UNLCK if none
    pub(crate) fn getlk(
        &self,
        nodeid: u64,
        fh: Option<u64>,
        owner: u64,
        start: u64,
        end: u64,
        typ: i32,
    ) -> FuseResult<fuse_file_lock> {
        let handle = match fh {
            Some(_) => None,
            None => Some(self.acquire(nodeid, false)?),
        };
        let fh = fh.or(handle.as_ref().map(|h| h.fh)).unwrap_or_default();
        let arg = lk_in(fh, owner, start, end, typ);
        let out: fuse_lk_out =
            decode(&self.call(fuse_opcode::FUSE_GETLK, nodeid, &[arg.as_bytes()])?)?;
        Ok(out.lk)
    }

    /// Reads up to `count` bytes, splitting the read into FUSE-sized requests. Returns the data
    /// and whether it ends at the end of the file
    pub(crate) fn read(&self, nodeid: u64, offset: u64, count: u32) -> FuseResult<(Vec<u8>, bool)> {
        let handle = self.acquire(nodeid, false)?;
        self.read_with(nodeid, handle.fh, handle.flags, offset, count)
    }

    /// `read` through the open file handle `fh`
    pub(crate) fn read_with(
        &self,
        nodeid: u64,
        fh: u64,
        flags: i32,
        offset: u64,
        count: u32,
    ) -> FuseResult<(Vec<u8>, bool)> {
        let mut data = Vec::new();
        while data.len() < count as usize {
            let want = (count - data.len() as u32).min(MAX_READ);
            let mut arg = fuse_read_in::new_zeroed();
            arg.fh = fh;
            arg.offset = offset + data.len() as u64;
            arg.size = want;
            arg.flags = flags;
            let chunk = self.call(fuse_opcode::FUSE_READ, nodeid, &[arg.as_bytes()])?;
            data.extend_from_slice(&chunk[..chunk.len().min(want as usize)]);
            if chunk.len() < want as usize {
                // Short reads mean the end of the file, as for the kernel without direct_io
                return Ok((data, true));
            }
        }
        Ok((data, false))
    }

    /// Has the filesystem make what was written to the node durable, through a handle that
    /// wrote to it if one is open
    pub(crate) fn fsync(&self, nodeid: u64) -> FuseResult<()> {
        if self.0.no_fsync.load(Ordering::Relaxed) {
            return Ok(());
        }
        let handle = self
            .acquire(nodeid, true)
            .or_else(|_| self.acquire(nodeid, false))?;
        self.fsync_with(nodeid, handle.fh)
    }

    /// Syncs a file through the handle `fh`, as fsync(2) on a descriptor does
    pub(crate) fn fsync_with(&self, nodeid: u64, fh: u64) -> FuseResult<()> {
        if self.0.no_fsync.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut arg = fuse_fsync_in::new_zeroed();
        arg.fh = fh;
        match self.call(fuse_opcode::FUSE_FSYNC, nodeid, &[arg.as_bytes()]) {
            Ok(_) => Ok(()),
            Err(libc::ENOSYS) => {
                self.0.no_fsync.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(errno) => Err(errno),
        }
    }

    /// Writes all of `data`, splitting it to the session's `max_write`
    pub(crate) fn write(&self, nodeid: u64, offset: u64, data: &[u8]) -> FuseResult<()> {
        let handle = self.acquire(nodeid, true)?;
        self.write_with(nodeid, handle.fh, handle.flags, offset, data)
    }

    /// `write` through the open file handle `fh`
    pub(crate) fn write_with(
        &self,
        nodeid: u64,
        fh: u64,
        flags: i32,
        offset: u64,
        data: &[u8],
    ) -> FuseResult<()> {
        let max_write = self.max_write()? as usize;
        let mut written = 0;
        while written < data.len() {
            let chunk = &data[written..data.len().min(written + max_write)];
            let mut arg = fuse_write_in::new_zeroed();
            arg.fh = fh;
            arg.offset = i64::try_from(offset + written as u64).map_err(|_| libc::EFBIG)?;
            arg.size = chunk.len() as u32;
            arg.flags = flags;
            let out: fuse_write_out =
                decode(&self.call(fuse_opcode::FUSE_WRITE, nodeid, &[arg.as_bytes(), chunk])?)?;
            if out.size == 0 {
                return Err(libc::EIO);
            }
            written += (out.size as usize).min(chunk.len());
        }
        Ok(())
    }

    /// Creates a regular file, keeping the handle `FUSE_CREATE` opens for the writes that follow:
    /// the file may well have been created without write permission, which only this handle
    /// gets past
    pub(crate) fn create(
        &self,
        dir: u64,
        name: &[u8],
        mode: u32,
        exclusive: bool,
    ) -> FuseResult<fuse_entry_out> {
        let (entry, opened) = self.create_open(dir, name, mode, exclusive)?;
        if let Some((fh, flags)) = opened {
            self.keep(entry.nodeid, fh, flags, 0);
        }
        Ok(entry)
    }

    /// Creates a regular file, returning the handle `FUSE_CREATE` opened, and its flags, for
    /// the caller to release. None if the filesystem has no CREATE, and MKNOD made the file
    pub(crate) fn create_open(
        &self,
        dir: u64,
        name: &[u8],
        mode: u32,
        exclusive: bool,
    ) -> FuseResult<(fuse_entry_out, Option<(u64, i32)>)> {
        let mut flags = libc::O_RDWR | libc::O_CREAT;
        if exclusive {
            flags |= libc::O_EXCL;
        }
        let arg = fuse_create_in {
            flags,
            mode: S_IFREG | (mode & 0o7777),
            umask: 0,
            open_flags: 0,
        };
        match self.call(
            fuse_opcode::FUSE_CREATE,
            dir,
            &[arg.as_bytes(), name, b"\0"],
        ) {
            Ok(reply) => {
                let entry: fuse_entry_out = decode(&reply)?;
                let open: fuse_open_out =
                    decode(reply.get(size_of::<fuse_entry_out>()..).unwrap_or_default())?;
                Ok((entry, Some((open.fh, flags))))
            }
            // As the kernel does
            Err(libc::ENOSYS) => Ok((self.mknod(dir, name, S_IFREG | (mode & 0o7777), 0)?, None)),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn mknod(
        &self,
        dir: u64,
        name: &[u8],
        mode: u32,
        rdev: u32,
    ) -> FuseResult<fuse_entry_out> {
        let arg = fuse_mknod_in {
            mode,
            rdev,
            umask: 0,
            padding: 0,
        };
        self.make(fuse_opcode::FUSE_MKNOD, dir, &[arg.as_bytes(), name, b"\0"])
    }

    /// Lists the directory from `cookie` on, while `fits` accepts each entry's name. Returns
    /// the entries, "." and ".." among them where the filesystem lists them, and whether they
    /// reach the end
    pub(crate) fn read_dir(
        &self,
        dir: u64,
        cookie: u64,
        mut fits: impl FnMut(&[u8]) -> bool,
    ) -> FuseResult<(Vec<DirEntry>, bool)> {
        let fh = match self.open(dir, fuse_opcode::FUSE_OPENDIR, libc::O_RDONLY) {
            Ok(fh) => fh,
            // As the kernel does, carry on without opening
            Err(libc::ENOSYS) => 0,
            Err(e) => return Err(e),
        };
        let mut entries = Vec::new();
        let mut offset = cookie;
        let result = 'pages: loop {
            let mut arg = fuse_read_in::new_zeroed();
            arg.fh = fh;
            arg.offset = offset;
            arg.size = READDIR_SIZE;
            arg.flags = libc::O_RDONLY;
            let data = match self.call(fuse_opcode::FUSE_READDIR, dir, &[arg.as_bytes()]) {
                Ok(data) => data,
                Err(e) => break Err(e),
            };
            let start = offset;
            let mut rest = &data[..];
            while let Ok((dirent, after)) = fuse_dirent::read_from_prefix(rest) {
                let Some(name) = after.get(..dirent.namelen as usize) else {
                    break;
                };
                if !fits(name) {
                    break 'pages Ok(false);
                }
                entries.push(DirEntry {
                    name: name.to_vec(),
                    ino: dirent.ino,
                    cookie: dirent.off,
                });
                offset = dirent.off;
                // Each entry is padded to 8 bytes
                let padded = (size_of::<fuse_dirent>() + name.len()).next_multiple_of(8);
                rest = rest.get(padded..).unwrap_or_default();
            }
            // The end, or no progress, which would otherwise loop forever
            if offset == start {
                break Ok(true);
            }
        };
        let mut release = fuse_release_in::new_zeroed();
        release.fh = fh;
        release.flags = libc::O_RDONLY;
        self.post(fuse_opcode::FUSE_RELEASEDIR, dir, &[release.as_bytes()]);
        result.map(|eof| (entries, eof))
    }
}

/// A file handle in use, given back to `Fuse` when dropped
struct HandleGuard {
    fuse: Fuse,
    nodeid: u64,
    id: u64,
    fh: u64,
    flags: i32,
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        let mut handles = self.fuse.0.handles.lock();
        if let Some(handle) = handles
            .get_mut(&self.nodeid)
            .and_then(|hs| hs.iter_mut().find(|h| h.id == self.id))
        {
            handle.users -= 1;
            handle.last_used = Instant::now();
        }
    }
}

fn lk_in(fh: u64, owner: u64, start: u64, end: u64, typ: i32) -> fuse_lk_in {
    fuse_lk_in {
        fh,
        owner,
        lk: fuse_file_lock {
            start,
            end,
            typ,
            pid: 0,
        },
        lk_flags: 0,
        padding: 0,
    }
}

/// Checks a reply's header, returning what follows it, or the error it carries
fn parse_reply(reply: &[u8]) -> FuseResult<&[u8]> {
    let (header, body) = fuse_out_header::read_from_prefix(reply).map_err(|_| libc::EIO)?;
    if header.error != 0 {
        return Err(-header.error);
    }
    Ok(body)
}

pub(crate) fn decode<T: FromBytes>(body: &[u8]) -> FuseResult<T> {
    T::read_from_prefix(body)
        .map(|(value, _)| value)
        .map_err(|_| libc::EIO)
}
