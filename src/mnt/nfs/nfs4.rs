//! NFSv4.1 (RFC 8881), experimental: COMPOUND and the operations a client needs to mount and
//! use one filesystem, answered with FUSE requests, next to the NFSv3 server.
//!
//! Each COMPOUND but those setting up a session starts with SEQUENCE, whose slot remembers the
//! last reply, so that a retransmitted request is answered again rather than run twice. Other
//! state is kept in its simplest form: client ids never expire, and there are no delegations,
//! callbacks or pNFS. OPEN and CLOSE map onto FUSE open and release. Byte-range locks go to
//! the filesystem's getlk and setlk, or to a table kept here when it has none.
//!
//! The root is a pseudo-filesystem whose one entry, the export, has a name made up for the
//! server, and can be looked up only until the mount is made: until a handle of the export is
//! used. From then on no new client is taken either. Like NFSv3's, file handles carry the
//! server's key, and client and session ids are random, so that other local users who can
//! connect cannot name a file, nor ask for the replies a session keeps.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Instant;

use log::debug;
use log::warn;
use parking_lot::Mutex;
use zerocopy::IntoBytes;

use super::fuse::DirEntry;
use super::fuse::Fuse;
use super::fuse::ROOT;
use super::fuse::S_IFDIR;
use super::fuse::S_IFMT;
use super::fuse::S_IFREG;
use super::nfs3::MAX_IO;
use super::nfs3::Name;
use super::nfs3::READDIR_BUDGET;
use super::nfs3::Refused;
use super::nfs3::Sattr;
use super::nfs3::SetTime;
use super::nfs3::name_arg;
use super::nfs3::nfsstat;
use super::nfs3::setattr_in;
use super::rpc::MAX_RECORD;
use super::rpc::SLOW_CALL;
use super::xdr;
use super::xdr::Reader;
use super::xdr::Writer;
use crate::ll::flags::fattr_flags::FattrFlags;
use crate::ll::fuse_abi::fuse_attr;
use crate::ll::fuse_abi::fuse_link_in;
use crate::ll::fuse_abi::fuse_mkdir_in;
use crate::ll::fuse_abi::fuse_opcode;
use crate::ll::fuse_abi::fuse_rename_in;

/// The node id of the pseudo-root, which no FUSE node has
const PSEUDO: u64 = 0;
// fcntl lock types, as FUSE carries them: c_short on macOS
#[allow(clippy::unnecessary_cast)]
const F_RDLCK: i32 = libc::F_RDLCK as i32;
#[allow(clippy::unnecessary_cast)]
const F_WRLCK: i32 = libc::F_WRLCK as i32;
#[allow(clippy::unnecessary_cast)]
const F_UNLCK: i32 = libc::F_UNLCK as i32;
const LEASE_TIME: u32 = 90;
/// The largest offset FUSE's locks carry: theirs are signed
const OFFSET_MAX: u64 = i64::MAX as u64;
// ACCESS bits
const ACCESS4_READ: u32 = 0x1;
const ACCESS4_LOOKUP: u32 = 0x2;
const ACCESS4_EXECUTE: u32 = 0x20;

// Operations: those answered, by number
const OP_ACCESS: u32 = 3;
const OP_CLOSE: u32 = 4;
const OP_COMMIT: u32 = 5;
const OP_CREATE: u32 = 6;
const OP_DELEGRETURN: u32 = 8;
const OP_GETATTR: u32 = 9;
const OP_GETFH: u32 = 10;
const OP_LINK: u32 = 11;
const OP_LOCK: u32 = 12;
const OP_LOCKT: u32 = 13;
const OP_LOCKU: u32 = 14;
const OP_LOOKUP: u32 = 15;
const OP_LOOKUPP: u32 = 16;
const OP_OPEN: u32 = 18;
const OP_OPEN_DOWNGRADE: u32 = 21;
const OP_PUTFH: u32 = 22;
const OP_PUTPUBFH: u32 = 23;
const OP_PUTROOTFH: u32 = 24;
const OP_READ: u32 = 25;
const OP_READDIR: u32 = 26;
const OP_READLINK: u32 = 27;
const OP_REMOVE: u32 = 28;
const OP_RENAME: u32 = 29;
const OP_RESTOREFH: u32 = 31;
const OP_SAVEFH: u32 = 32;
const OP_SECINFO: u32 = 33;
const OP_SETATTR: u32 = 34;
const OP_WRITE: u32 = 38;
const OP_BACKCHANNEL_CTL: u32 = 40;
const OP_BIND_CONN_TO_SESSION: u32 = 41;
const OP_EXCHANGE_ID: u32 = 42;
const OP_CREATE_SESSION: u32 = 43;
const OP_DESTROY_SESSION: u32 = 44;
const OP_FREE_STATEID: u32 = 45;
const OP_SECINFO_NO_NAME: u32 = 52;
const OP_SEQUENCE: u32 = 53;
const OP_TEST_STATEID: u32 = 55;
const OP_DESTROY_CLIENTID: u32 = 57;
const OP_RECLAIM_COMPLETE: u32 = 58;
const OP_ILLEGAL: u32 = 10044;

// nfsstat4, beyond those NFSv3 shares
const NFS4_OK: u32 = 0;
const NFS4ERR_PERM: u32 = 1;
const NFS4ERR_NOENT: u32 = 2;
const NFS4ERR_NOSPC: u32 = 28;
const NFS4ERR_ACCESS: u32 = 13;
const NFS4ERR_EXIST: u32 = 17;
const NFS4ERR_ISDIR: u32 = 21;
const NFS4ERR_INVAL: u32 = 22;
const NFS4ERR_ROFS: u32 = 30;
const NFS4ERR_BADHANDLE: u32 = 10001;
const NFS4ERR_BAD_COOKIE: u32 = 10003;
const NFS4ERR_NOTSUPP: u32 = 10004;
const NFS4ERR_TOOSMALL: u32 = 10005;
const NFS4ERR_BADTYPE: u32 = 10007;
const NFS4ERR_DELAY: u32 = 10008;
const NFS4ERR_DENIED: u32 = 10010;
const NFS4ERR_NOFILEHANDLE: u32 = 10020;
const NFS4ERR_MINOR_VERS_MISMATCH: u32 = 10021;
const NFS4ERR_STALE_CLIENTID: u32 = 10022;
const NFS4ERR_BAD_STATEID: u32 = 10025;
const NFS4ERR_NOT_SAME: u32 = 10027;
const NFS4ERR_LOCK_RANGE: u32 = 10028;
const NFS4ERR_SYMLINK: u32 = 10029;
const NFS4ERR_RESTOREFH: u32 = 10030;
const NFS4ERR_ATTRNOTSUPP: u32 = 10032;
const NFS4ERR_NO_GRACE: u32 = 10033;
const NFS4ERR_BADXDR: u32 = 10036;
const NFS4ERR_LOCKS_HELD: u32 = 10037;
const NFS4ERR_BADOWNER: u32 = 10039;
const NFS4ERR_BADNAME: u32 = 10041;
const NFS4ERR_OP_ILLEGAL: u32 = 10044;
const NFS4ERR_BADSESSION: u32 = 10052;
const NFS4ERR_BADSLOT: u32 = 10053;
const NFS4ERR_SEQ_MISORDERED: u32 = 10063;
const NFS4ERR_SEQUENCE_POS: u32 = 10064;
const NFS4ERR_REP_TOO_BIG: u32 = 10066;
const NFS4ERR_RETRY_UNCACHED_REP: u32 = 10068;
const NFS4ERR_TOO_MANY_OPS: u32 = 10070;
const NFS4ERR_OP_NOT_IN_SESSION: u32 = 10071;
const NFS4ERR_CLIENTID_BUSY: u32 = 10074;
const NFS4ERR_NOT_ONLY_OP: u32 = 10081;

// EXCHANGE_ID and CREATE_SESSION flags
const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x0001_0000;
const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A: u32 = 0x4000_0000;
const EXCHGID4_FLAG_CONFIRMED_R: u32 = 0x8000_0000;
const CREATE_SESSION4_FLAG_CONN_BACK_CHAN: u32 = 2;

/// Slots in a session's table: requests a client may have outstanding at once
const MAX_SLOTS: u32 = 16;
/// Operations in a COMPOUND
const MAX_OPS: u32 = 128;
/// Replies cached even when the client did not ask, as they are small
const SMALL_REPLY: usize = 4096;
/// Clients and sessions kept at once: a mount needs one client, and a session or two
const MAX_CLIENTS: usize = 64;
const MAX_SESSIONS: usize = 64;

// nfs_ftype4
const NF4REG: u32 = 1;
const NF4DIR: u32 = 2;
const NF4BLK: u32 = 3;
const NF4CHR: u32 = 4;
const NF4LNK: u32 = 5;
const NF4SOCK: u32 = 6;
const NF4FIFO: u32 = 7;

// Attributes, by bit
const A_SUPPORTED_ATTRS: u32 = 0;
const A_TYPE: u32 = 1;
const A_FH_EXPIRE_TYPE: u32 = 2;
const A_CHANGE: u32 = 3;
const A_SIZE: u32 = 4;
const A_LINK_SUPPORT: u32 = 5;
const A_SYMLINK_SUPPORT: u32 = 6;
const A_NAMED_ATTR: u32 = 7;
const A_FSID: u32 = 8;
const A_UNIQUE_HANDLES: u32 = 9;
const A_LEASE_TIME: u32 = 10;
const A_RDATTR_ERROR: u32 = 11;
const A_ARCHIVE: u32 = 14;
const A_CANSETTIME: u32 = 15;
const A_CASE_INSENSITIVE: u32 = 16;
const A_CASE_PRESERVING: u32 = 17;
const A_CHOWN_RESTRICTED: u32 = 18;
const A_FILEHANDLE: u32 = 19;
const A_FILEID: u32 = 20;
const A_FILES_AVAIL: u32 = 21;
const A_FILES_FREE: u32 = 22;
const A_FILES_TOTAL: u32 = 23;
const A_HIDDEN: u32 = 25;
const A_HOMOGENEOUS: u32 = 26;
const A_MAXFILESIZE: u32 = 27;
const A_MAXLINK: u32 = 28;
const A_MAXNAME: u32 = 29;
const A_MAXREAD: u32 = 30;
const A_MAXWRITE: u32 = 31;
const A_MODE: u32 = 33;
const A_NO_TRUNC: u32 = 34;
const A_NUMLINKS: u32 = 35;
const A_OWNER: u32 = 36;
const A_OWNER_GROUP: u32 = 37;
const A_RAWDEV: u32 = 41;
const A_SPACE_AVAIL: u32 = 42;
const A_SPACE_FREE: u32 = 43;
const A_SPACE_TOTAL: u32 = 44;
const A_SPACE_USED: u32 = 45;
const A_SYSTEM: u32 = 46;
const A_TIME_ACCESS: u32 = 47;
const A_TIME_ACCESS_SET: u32 = 48;
const A_TIME_CREATE: u32 = 50;
const A_TIME_DELTA: u32 = 51;
const A_TIME_METADATA: u32 = 52;
const A_TIME_MODIFY: u32 = 53;
const A_TIME_MODIFY_SET: u32 = 54;
const A_MOUNTED_ON_FILEID: u32 = 55;
const A_SUPPATTR_EXCLCREAT: u32 = 75;

/// Attributes an EXCLUSIVE4_1 create sets
const EXCLCREAT: &[u32] = &[
    A_SIZE,
    A_MODE,
    A_OWNER,
    A_OWNER_GROUP,
    A_TIME_ACCESS_SET,
    A_TIME_MODIFY_SET,
];

/// An attribute bitmap4, of the words this server knows
type Bitmap = [u32; 3];

/// What GETATTR answers. The two `_SET` attributes are settable only
const SUPPORTED: &[u32] = &[
    A_SUPPORTED_ATTRS,
    A_TYPE,
    A_FH_EXPIRE_TYPE,
    A_CHANGE,
    A_SIZE,
    A_LINK_SUPPORT,
    A_SYMLINK_SUPPORT,
    A_NAMED_ATTR,
    A_FSID,
    A_UNIQUE_HANDLES,
    A_LEASE_TIME,
    A_RDATTR_ERROR,
    A_CANSETTIME,
    A_CASE_INSENSITIVE,
    A_CASE_PRESERVING,
    A_CHOWN_RESTRICTED,
    A_FILEHANDLE,
    A_FILEID,
    A_FILES_AVAIL,
    A_FILES_FREE,
    A_FILES_TOTAL,
    A_HOMOGENEOUS,
    A_MAXFILESIZE,
    A_MAXLINK,
    A_MAXNAME,
    A_MAXREAD,
    A_MAXWRITE,
    A_MODE,
    A_NO_TRUNC,
    A_NUMLINKS,
    A_OWNER,
    A_OWNER_GROUP,
    A_RAWDEV,
    A_SPACE_AVAIL,
    A_SPACE_FREE,
    A_SPACE_TOTAL,
    A_SPACE_USED,
    A_TIME_ACCESS,
    A_TIME_ACCESS_SET,
    A_TIME_DELTA,
    A_TIME_METADATA,
    A_TIME_MODIFY,
    A_TIME_MODIFY_SET,
    A_MOUNTED_ON_FILEID,
    A_SUPPATTR_EXCLCREAT,
];

/// How an operation failed
#[derive(Debug)]
enum Error {
    Garbage,
    Errno(i32),
    Status(u32),
    /// NFS4ERR_DENIED, with the LOCK4denied that says by what
    Denied(Vec<u8>),
}

impl From<xdr::Garbage> for Error {
    fn from(_: xdr::Garbage) -> Self {
        Error::Garbage
    }
}

impl From<i32> for Error {
    fn from(errno: i32) -> Self {
        Error::Errno(errno)
    }
}

type Result<T = ()> = std::result::Result<T, Error>;

/// What SEQUENCE found
#[derive(Debug)]
enum Sequenced {
    /// A new request, which has taken the slot
    New,
    /// A retransmission, with the reply it had
    Replay(Vec<u8>),
    /// A retransmission whose reply was not kept
    Uncached,
}

/// What a COMPOUND without SEQUENCE may do, alone
const SESSIONLESS: &[u32] = &[
    OP_EXCHANGE_ID,
    OP_CREATE_SESSION,
    OP_DESTROY_SESSION,
    OP_BIND_CONN_TO_SESSION,
    OP_DESTROY_CLIENTID,
];

/// What a COMPOUND's operations leave for those after them
#[derive(Debug, Default)]
struct Ctx {
    current: Option<u64>,
    saved: Option<u64>,
    /// The current stateid, which the special stateid {1, 0} stands for, and the saved one
    stateid: Option<u64>,
    saved_stateid: Option<u64>,
    /// The client of the session that SEQUENCE named
    clientid: Option<u64>,
    /// The session and slot SEQUENCE took, and whether the client asked for the reply to be
    /// cached
    slot: Option<([u8; 16], u32, bool)>,
    /// The largest reply the session takes
    max_response: Option<usize>,
}

impl Ctx {
    fn current(&self) -> Result<u64> {
        self.current.ok_or(Error::Status(NFS4ERR_NOFILEHANDLE))
    }

    /// The current handle, which must not be the pseudo-root's
    fn file(&self) -> Result<u64> {
        match self.current()? {
            PSEUDO => Err(Error::Status(NFS4ERR_ACCESS)),
            node => Ok(node),
        }
    }

    /// The client of the session, or the one an operation names outside of one
    fn client(&self, named: u64) -> u64 {
        self.clientid.unwrap_or(named)
    }

    /// Decodes a stateid: None for the anonymous and read-bypass ones
    fn stateid(&self, a: &mut Reader<'_>) -> Result<Option<u64>> {
        let seqid = a.u32()?;
        let other = a.fixed(12)?;
        if other.iter().all(|b| *b == 0) {
            if seqid == 1 {
                return self
                    .stateid
                    .map(Some)
                    .ok_or(Error::Status(NFS4ERR_BAD_STATEID));
            }
            return Ok(None);
        }
        if other.iter().all(|b| *b == 0xff) {
            return Ok(None);
        }
        Ok(Some(u64::from_be_bytes(
            other[..8].try_into().expect("8 bytes"),
        )))
    }
}

/// A client, as EXCHANGE_ID records it
#[derive(Debug)]
struct Client {
    owner: Vec<u8>,
    verifier: [u8; 8],
    /// A session has been made for it
    confirmed: bool,
    /// The csa_sequence the next CREATE_SESSION carries
    sequence: u32,
    /// The reply to the last CREATE_SESSION, for its retransmission
    created: Option<Vec<u8>>,
}

#[derive(Debug, Default, Clone)]
struct Slot {
    /// The sequence id of the request last taken
    sequence: u32,
    /// That request is being answered
    busy: bool,
    /// It was retransmitted meanwhile, so its reply is kept for the retransmission, however
    /// large
    retransmitted: bool,
    /// Its reply, if cached
    reply: Option<Vec<u8>>,
}

#[derive(Debug)]
struct Session {
    clientid: u64,
    slots: Vec<Slot>,
    max_ops: u32,
    max_response: usize,
    max_cached: usize,
}

/// An open: a FUSE file handle, for one open-owner and file
#[derive(Debug)]
struct Open {
    node: u64,
    fh: u64,
    flags: i32,
    owner: (u64, Vec<u8>),
    seqid: u32,
}

/// A lock-owner's locks on the file of an open
#[derive(Debug)]
struct LockState {
    open: u64,
    owner: u64,
    seqid: u32,
}

/// A byte-range lock in the table kept for filesystems without getlk and setlk
#[derive(Debug, Clone, Copy)]
struct Range {
    owner: u64,
    start: u64,
    end: u64,
    write: bool,
}

#[derive(Debug, Default)]
struct State {
    clients: HashMap<u64, Client>,
    sessions: HashMap<[u8; 16], Session>,
    opens: HashMap<u64, Open>,
    locks: HashMap<u64, LockState>,
    /// Lock-owners, by client and owner, as the owner ids FUSE locks carry
    lock_owners: HashMap<(u64, Vec<u8>), u64>,
    /// The locks kept here, by node, for filesystems without getlk and setlk
    ranges: HashMap<u64, Vec<Range>>,
    next: u64,
}

impl State {
    fn new_id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn lock_owner(&mut self, clientid: u64, owner: &[u8]) -> u64 {
        let key = (clientid, owner.to_vec());
        if let Some(&id) = self.lock_owners.get(&key) {
            return id;
        }
        let id = self.new_id();
        self.lock_owners.insert(key, id);
        id
    }

    /// Forgets a client and everything it holds, returning the opens to release
    fn drop_client(&mut self, clientid: u64) -> Vec<Open> {
        self.clients.remove(&clientid);
        self.sessions
            .retain(|_, session| session.clientid != clientid);
        let ids: Vec<u64> = self
            .opens
            .iter()
            .filter(|(_, open)| open.owner.0 == clientid)
            .map(|(id, _)| *id)
            .collect();
        let opens: Vec<Open> = ids.iter().filter_map(|id| self.opens.remove(id)).collect();
        self.locks.retain(|_, lock| !ids.contains(&lock.open));
        let owners: Vec<u64> = self
            .lock_owners
            .iter()
            .filter(|((client, _), _)| *client == clientid)
            .map(|(_, id)| *id)
            .collect();
        self.lock_owners
            .retain(|(client, _), _| *client != clientid);
        for ranges in self.ranges.values_mut() {
            ranges.retain(|r| !owners.contains(&r.owner));
        }
        opens
    }
}

/// The NFSv4.1 side of the server
#[derive(Debug)]
pub(crate) struct Nfs4 {
    fuse: Fuse,
    read_only: bool,
    key: [u8; 8],
    verifier: [u8; 8],
    /// The export's name under the pseudo-root
    export: Vec<u8>,
    /// The export can no longer be looked up: the mount has been made, or is NFSv3
    sealed: AtomicBool,
    /// The filesystem answered getlk or setlk with ENOSYS, so locks are kept here
    local_locks: AtomicBool,
    state: Mutex<State>,
}

impl Nfs4 {
    pub(crate) fn new(
        fuse: Fuse,
        read_only: bool,
        key: [u8; 8],
        verifier: [u8; 8],
        export: String,
        sealed: bool,
    ) -> Self {
        Self {
            fuse,
            read_only,
            key,
            verifier,
            export: export.into_bytes(),
            sealed: AtomicBool::new(sealed),
            local_locks: AtomicBool::new(false),
            state: Mutex::default(),
        }
    }

    /// The path `mount_nfs` mounts
    pub(crate) fn export_path(&self) -> String {
        format!("/{}", String::from_utf8_lossy(&self.export))
    }

    /// Stops the export being looked up, and new clients being taken, once the mount that needs
    /// it is made
    pub(crate) fn seal(&self) {
        self.sealed.store(true, Ordering::SeqCst);
    }

    /// Runs NFSv4 procedure `proc`: NULL or COMPOUND
    pub(crate) fn call(&self, proc: u32, args: &[u8]) -> std::result::Result<Vec<u8>, Refused> {
        match proc {
            0 => Ok(Vec::new()),
            1 => self.compound(args).map_err(|_| Refused::Garbage),
            _ => Err(Refused::NoProcedure),
        }
    }

    fn compound(&self, args: &[u8]) -> xdr::Result<Vec<u8>> {
        let a = &mut Reader::new(args);
        let tag = a.opaque()?.to_vec();
        let minor = a.u32()?;
        let count = a.u32()?;
        let mut results = Vec::new();
        let mut done = 0u32;
        let mut status = NFS4_OK;
        let mut c = Ctx::default();
        let mut uncached = false;
        let mut ops = Vec::new();
        let started = Instant::now();
        if minor != 1 {
            status = NFS4ERR_MINOR_VERS_MISMATCH;
        }
        for i in 0..count {
            if status != NFS4_OK {
                break;
            }
            let op = match a.u32() {
                Ok(op) => op,
                Err(_) => {
                    status = NFS4ERR_BADXDR;
                    break;
                }
            };
            ops.push(op);
            let known = (OP_ACCESS..=OP_RECLAIM_COMPLETE).contains(&op);
            let start = results.len();
            results.put_u32(if known { op } else { OP_ILLEGAL });
            results.put_u32(NFS4_OK);
            done += 1;
            let result = if !known {
                Err(Error::Status(NFS4ERR_OP_ILLEGAL))
            } else if op == OP_SEQUENCE && i > 0 {
                Err(Error::Status(NFS4ERR_SEQUENCE_POS))
            } else if op == OP_SEQUENCE {
                match self.sequence(a, &mut results, count, &mut c) {
                    Ok(Sequenced::Replay(reply)) => return Ok(reply),
                    Ok(Sequenced::Uncached) => {
                        uncached = true;
                        Ok(())
                    }
                    Ok(Sequenced::New) => Ok(()),
                    Err(err) => Err(err),
                }
            } else if i == 0 && !SESSIONLESS.contains(&op) {
                Err(Error::Status(NFS4ERR_OP_NOT_IN_SESSION))
            } else if i == 0 && count > 1 {
                Err(Error::Status(NFS4ERR_NOT_ONLY_OP))
            } else if uncached {
                // A retransmission whose reply was not kept: it is not run again
                Err(Error::Status(NFS4ERR_RETRY_UNCACHED_REP))
            } else {
                self.op(op, a, &mut results, &mut c)
            };
            if let Err(err) = result {
                let (code, extra) = match err {
                    Error::Garbage => (NFS4ERR_BADXDR, Vec::new()),
                    Error::Errno(errno) => (nfsstat(errno), Vec::new()),
                    Error::Status(code) => (code, Vec::new()),
                    Error::Denied(denied) => (NFS4ERR_DENIED, denied),
                };
                results.truncate(start + 4);
                results.put_u32(code);
                results.extend_from_slice(&extra);
                // SETATTR answers with the attributes it set even when it fails: none here
                if op == OP_SETATTR {
                    results.put_u32(0);
                }
                status = code;
            }
            // The status, tag and count before the results, with room for the RPC's header
            let size = 12 + tag.len().next_multiple_of(4) + results.len() + 64;
            if status == NFS4_OK && c.max_response.is_some_and(|max| size > max) {
                results.truncate(start + 4);
                results.put_u32(NFS4ERR_REP_TOO_BIG);
                status = NFS4ERR_REP_TOO_BIG;
            }
        }
        let took = started.elapsed();
        if took > SLOW_CALL {
            warn!("NFSv4 COMPOUND {ops:?} took {took:?}: status {status}");
        } else {
            debug!("NFSv4 COMPOUND {ops:?}: status {status}");
        }
        let mut out = Vec::new();
        out.put_u32(status);
        out.put_opaque(&tag);
        out.put_u32(done);
        out.extend_from_slice(&results);
        if let Some((session, slot, cache)) = c.slot {
            self.finish(session, slot, cache, &out);
        }
        Ok(out)
    }

    /// Takes the slot SEQUENCE names, or finds the request a retransmission
    fn sequence(
        &self,
        a: &mut Reader<'_>,
        out: &mut Vec<u8>,
        count: u32,
        c: &mut Ctx,
    ) -> Result<Sequenced> {
        let id: [u8; 16] = a.fixed(16)?.try_into().expect("16 bytes");
        let sequence = a.u32()?;
        let slotid = a.u32()?;
        a.u32()?;
        let cache = a.bool()?;
        let mut state = self.state.lock();
        let session = state
            .sessions
            .get_mut(&id)
            .ok_or(Error::Status(NFS4ERR_BADSESSION))?;
        if count > session.max_ops {
            return Err(Error::Status(NFS4ERR_TOO_MANY_OPS));
        }
        let highest = session.slots.len() as u32 - 1;
        let clientid = session.clientid;
        let max_response = session.max_response;
        let slot = session
            .slots
            .get_mut(slotid as usize)
            .ok_or(Error::Status(NFS4ERR_BADSLOT))?;
        let sequenced = if sequence == slot.sequence.wrapping_add(1) && !slot.busy {
            slot.sequence = sequence;
            slot.busy = true;
            slot.retransmitted = false;
            slot.reply = None;
            c.slot = Some((id, slotid, cache));
            Sequenced::New
        } else if sequence == slot.sequence {
            if slot.busy {
                slot.retransmitted = true;
                return Err(Error::Status(NFS4ERR_DELAY));
            }
            match &slot.reply {
                Some(reply) => return Ok(Sequenced::Replay(reply.clone())),
                None => Sequenced::Uncached,
            }
        } else {
            return Err(Error::Status(NFS4ERR_SEQ_MISORDERED));
        };
        c.clientid = Some(clientid);
        c.max_response = Some(max_response);
        out.put_fixed(&id);
        out.put_u32(sequence);
        out.put_u32(slotid);
        // The highest slot, and the one wanted: all of them
        out.put_u32(highest);
        out.put_u32(highest);
        out.put_u32(0);
        Ok(sequenced)
    }

    /// Frees a slot once its reply is made, keeping the reply if asked to, if it is small, or if
    /// the request was retransmitted while it was answered
    fn finish(&self, id: [u8; 16], slotid: u32, cache: bool, reply: &[u8]) {
        let mut state = self.state.lock();
        // Gone if the COMPOUND destroyed it
        let Some(session) = state.sessions.get_mut(&id) else {
            return;
        };
        let max_cached = session.max_cached;
        if let Some(slot) = session.slots.get_mut(slotid as usize) {
            let keep = slot.retransmitted
                || ((cache || reply.len() <= SMALL_REPLY) && reply.len() <= max_cached);
            slot.busy = false;
            slot.reply = keep.then(|| reply.to_vec());
        }
    }

    fn op(&self, op: u32, a: &mut Reader<'_>, out: &mut Vec<u8>, c: &mut Ctx) -> Result {
        let modifies = matches!(
            op,
            OP_CREATE | OP_LINK | OP_REMOVE | OP_RENAME | OP_SETATTR | OP_WRITE
        );
        if self.read_only && modifies {
            return Err(Error::Status(NFS4ERR_ROFS));
        }
        match op {
            OP_PUTROOTFH | OP_PUTPUBFH => {
                c.current = Some(PSEUDO);
                c.stateid = None;
            }
            OP_PUTFH => {
                let node = self.handle(a)?;
                // A handle of the export in use: the mount is made, so its name may be seen
                if node != PSEUDO {
                    self.seal();
                }
                c.current = Some(node);
                c.stateid = None;
            }
            OP_GETFH => self.put_handle(out, c.current()?),
            OP_SAVEFH => {
                c.saved = Some(c.current()?);
                c.saved_stateid = c.stateid;
            }
            OP_RESTOREFH => {
                c.current = Some(c.saved.ok_or(Error::Status(NFS4ERR_RESTOREFH))?);
                c.stateid = c.saved_stateid;
            }
            OP_LOOKUP => {
                let name = name4(a.opaque()?, Name::Lookup)?;
                c.current = Some(self.lookup(c.current()?, name)?);
            }
            OP_LOOKUPP => {
                c.current = Some(match c.current()? {
                    PSEUDO => return Err(Error::Status(NFS4ERR_NOENT)),
                    ROOT => PSEUDO,
                    node => self.fuse.resolve(node, b"..")?,
                });
            }
            OP_GETATTR => {
                let request = bitmap(a)?;
                self.put_fattr(out, c.current()?, &request)?;
            }
            OP_ACCESS => {
                let access = a.u32()?;
                let granted = match c.current()? {
                    // The pseudo-root may be read and searched, not changed
                    PSEUDO => access & (ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_EXECUTE),
                    node => self.fuse.granted_access(node, access)?,
                };
                // supported: every bit asked about is answered
                out.put_u32(access);
                out.put_u32(granted);
            }
            OP_READLINK => {
                let target = self.fuse.call(fuse_opcode::FUSE_READLINK, c.file()?, &[])?;
                out.put_opaque(&target);
            }
            OP_READ => self.read(a, out, c)?,
            OP_WRITE => self.write(a, out, c)?,
            OP_COMMIT => {
                a.u64()?;
                a.u32()?;
                self.commit(c.file()?)?;
                out.put_fixed(&self.verifier);
            }
            OP_CREATE => self.create(a, out, c)?,
            OP_REMOVE => {
                let name = name4(a.opaque()?, Name::Rmdir)?;
                let dir = c.file()?;
                let entry = self.fuse.lookup(dir, name)?;
                let opcode = if entry.attr.mode & S_IFMT == S_IFDIR {
                    fuse_opcode::FUSE_RMDIR
                } else {
                    fuse_opcode::FUSE_UNLINK
                };
                self.fuse.call(opcode, dir, &[name, b"\0"])?;
                put_change_info(out);
            }
            OP_RENAME => {
                let from = name4(a.opaque()?, Name::Rename)?;
                let to = name4(a.opaque()?, Name::Rename)?;
                let from_dir = c.saved.ok_or(Error::Status(NFS4ERR_NOFILEHANDLE))?;
                let to_dir = c.file()?;
                if from_dir == PSEUDO {
                    return Err(Error::Status(NFS4ERR_ACCESS));
                }
                let arg = fuse_rename_in { newdir: to_dir };
                self.fuse.call(
                    fuse_opcode::FUSE_RENAME,
                    from_dir,
                    &[arg.as_bytes(), from, b"\0", to, b"\0"],
                )?;
                if from_dir != to_dir {
                    // If a directory moved, this records its new parent for LOOKUPP
                    let _ = self.fuse.lookup(to_dir, to);
                }
                put_change_info(out);
                put_change_info(out);
            }
            OP_LINK => {
                let name = name4(a.opaque()?, Name::Create)?;
                let node = c.saved.ok_or(Error::Status(NFS4ERR_NOFILEHANDLE))?;
                let arg = fuse_link_in { oldnodeid: node };
                self.fuse.make(
                    fuse_opcode::FUSE_LINK,
                    c.file()?,
                    &[arg.as_bytes(), name, b"\0"],
                )?;
                put_change_info(out);
            }
            OP_SETATTR => {
                let id = c.stateid(a)?;
                let attrs = settable(a)?;
                let node = c.file()?;
                if let Some(mut arg) = setattr_in(&attrs.sattr, false) {
                    // A size set through an open for writing is an ftruncate: the
                    // filesystem is told the handle, as it may allow what the file's mode
                    // would not
                    if let Some((fh, flags)) = self.open_of(id, node)? {
                        if attrs.sattr.size.is_some() && flags & libc::O_ACCMODE != libc::O_RDONLY {
                            arg.fh = fh;
                            arg.valid |= FattrFlags::FATTR_FH.bits();
                        }
                    }
                    self.fuse.setattr(node, &arg)?;
                }
                put_bitmap(out, &attrs.mask);
            }
            OP_READDIR => self.readdir(a, out, c.current()?)?,
            OP_SECINFO | OP_SECINFO_NO_NAME => {
                let node = c.current()?;
                if op == OP_SECINFO {
                    a.opaque()?;
                } else if a.u32()? == 1 && node == PSEUDO {
                    // SECINFO_STYLE4_PARENT of the pseudo-root
                    return Err(Error::Status(NFS4ERR_NOENT));
                }
                // AUTH_SYS only
                out.put_u32(1);
                out.put_u32(1);
                // Both consume the current handle
                c.current = None;
            }
            OP_EXCHANGE_ID => self.exchange_id(a, out)?,
            OP_CREATE_SESSION => self.create_session(a, out)?,
            OP_DESTROY_SESSION => {
                let id = a.fixed(16)?;
                if self.state.lock().sessions.remove(id).is_none() {
                    return Err(Error::Status(NFS4ERR_BADSESSION));
                }
            }
            OP_BIND_CONN_TO_SESSION => {
                let id = a.fixed(16)?;
                let dir = a.u32()?;
                a.bool()?;
                if !self.state.lock().sessions.contains_key(id) {
                    return Err(Error::Status(NFS4ERR_BADSESSION));
                }
                out.put_fixed(id);
                // CDFS4_FORE, CDFS4_BACK or CDFS4_BOTH: connections are not told apart
                out.put_u32(match dir {
                    1 | 2 => dir,
                    _ => 3,
                });
                out.put_bool(false);
            }
            OP_BACKCHANNEL_CTL => {
                a.u32()?;
                for _ in 0..a.u32()? {
                    callback_sec_parms(a)?;
                }
            }
            OP_DESTROY_CLIENTID => {
                let clientid = a.u64()?;
                let opens = {
                    let mut state = self.state.lock();
                    if !state.clients.contains_key(&clientid) {
                        return Err(Error::Status(NFS4ERR_STALE_CLIENTID));
                    }
                    if state.sessions.values().any(|s| s.clientid == clientid) {
                        return Err(Error::Status(NFS4ERR_CLIENTID_BUSY));
                    }
                    state.drop_client(clientid)
                };
                self.release(opens);
            }
            // There is nothing to reclaim
            OP_RECLAIM_COMPLETE => {
                a.bool()?;
            }
            OP_TEST_STATEID => {
                let count = a.u32()?;
                let mut codes = Vec::new();
                for _ in 0..count {
                    a.u32()?;
                    let other = a.fixed(12)?;
                    let id = u64::from_be_bytes(other[..8].try_into().expect("8 bytes"));
                    let state = self.state.lock();
                    let known = other[8..] == [0; 4]
                        && (state.opens.contains_key(&id) || state.locks.contains_key(&id));
                    codes.put_u32(if known { NFS4_OK } else { NFS4ERR_BAD_STATEID });
                }
                out.put_u32(count);
                out.extend_from_slice(&codes);
            }
            OP_FREE_STATEID => {
                let id = c.stateid(a)?.ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
                let mut state = self.state.lock();
                // A lock-owner's stateid goes once it holds no locks: those kept here can be
                // seen, the filesystem's cannot
                let held = state.locks.get(&id).is_some_and(|lock| {
                    let node = state.opens.get(&lock.open).map_or(0, |open| open.node);
                    state
                        .ranges
                        .get(&node)
                        .is_some_and(|ranges| ranges.iter().any(|r| r.owner == lock.owner))
                });
                if held {
                    return Err(Error::Status(NFS4ERR_LOCKS_HELD));
                }
                if state.locks.remove(&id).is_none() {
                    // An open's is freed by CLOSE
                    return Err(Error::Status(if state.opens.contains_key(&id) {
                        NFS4ERR_LOCKS_HELD
                    } else {
                        NFS4ERR_BAD_STATEID
                    }));
                }
            }
            OP_OPEN => self.open(a, out, c)?,
            OP_OPEN_DOWNGRADE => {
                let id = c.stateid(a)?;
                a.u32()?;
                a.u32()?;
                a.u32()?;
                // The handle keeps the access it was opened with
                let mut state = self.state.lock();
                let open = id
                    .and_then(|id| state.opens.get_mut(&id))
                    .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
                open.seqid += 1;
                put_stateid(out, open.seqid, id.unwrap_or_default());
                c.stateid = id;
            }
            OP_CLOSE => {
                a.u32()?;
                let id = c.stateid(a)?.ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
                let (open, owners) = {
                    let mut state = self.state.lock();
                    let open = state
                        .opens
                        .remove(&id)
                        .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
                    let owners: Vec<u64> = state
                        .locks
                        .values()
                        .filter(|lock| lock.open == id)
                        .map(|lock| lock.owner)
                        .collect();
                    state.locks.retain(|_, lock| lock.open != id);
                    (open, owners)
                };
                // Its locks go with it, as a descriptor's do when it is closed
                for owner in owners {
                    let _ = self.set_lock(open.node, open.fh, owner, 0, OFFSET_MAX, None);
                }
                c.stateid = None;
                self.fuse
                    .close_file_checked(open.node, open.fh, open.flags)?;
                // The invalid stateid, as there is no open left
                put_stateid(out, u32::MAX, 0);
            }
            OP_LOCK => self.lock(a, out, c)?,
            OP_LOCKT => self.lockt(a, c)?,
            OP_LOCKU => self.locku(a, out, c)?,
            OP_DELEGRETURN => {
                // There are no delegations to return
                c.stateid(a)?;
                return Err(Error::Status(NFS4ERR_BAD_STATEID));
            }
            // NFSv4.0's client and open confirmation, which sessions replace, and what needs
            // named attributes, delegations or pNFS
            _ => return Err(Error::Status(NFS4ERR_NOTSUPP)),
        }
        Ok(())
    }

    /// Decodes a file handle: a node id, then this server's key
    fn handle(&self, a: &mut Reader<'_>) -> Result<u64> {
        let data = a.opaque()?;
        match (data.get(..8), data.get(8..)) {
            (Some(node), Some(key)) if key == self.key => {
                Ok(u64::from_be_bytes(node.try_into().expect("8 bytes")))
            }
            _ => Err(Error::Status(NFS4ERR_BADHANDLE)),
        }
    }

    fn put_handle(&self, out: &mut Vec<u8>, node: u64) {
        out.put_opaque(&[&node.to_be_bytes()[..], &self.key].concat());
    }

    fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64> {
        if dir == PSEUDO {
            return if name == self.export && !self.sealed.load(Ordering::SeqCst) {
                Ok(ROOT)
            } else {
                Err(Error::Status(NFS4ERR_NOENT))
            };
        }
        let entry = self.fuse.lookup(dir, name)?;
        Ok(entry.nodeid)
    }

    /// The attributes of a node, or made up for the pseudo-root
    fn attr(&self, node: u64) -> Result<fuse_attr> {
        if node != PSEUDO {
            return Ok(self.fuse.getattr(node)?);
        }
        let root = self.fuse.getattr(ROOT)?;
        Ok(fuse_attr {
            ino: u64::MAX,
            mode: S_IFDIR | 0o555,
            nlink: 2,
            size: 0,
            blocks: 0,
            ..root
        })
    }

    fn put_fattr(&self, out: &mut Vec<u8>, node: u64, request: &Bitmap) -> Result {
        let attr = self.attr(node)?;
        self.put_fattr_of(out, node, &attr, request)
    }

    fn put_fattr_of(
        &self,
        out: &mut Vec<u8>,
        node: u64,
        attr: &fuse_attr,
        request: &Bitmap,
    ) -> Result {
        let wanted = |bit: u32| is_set(request, bit);
        let needs_fs = [
            A_FILES_AVAIL,
            A_FILES_FREE,
            A_FILES_TOTAL,
            A_MAXNAME,
            A_SPACE_AVAIL,
            A_SPACE_FREE,
            A_SPACE_TOTAL,
        ]
        .into_iter()
        .any(wanted);
        let st = if needs_fs {
            Some(self.fuse.statfs(if node == PSEUDO { ROOT } else { node })?)
        } else {
            None
        };
        let mut mask = [0; 3];
        let mut v = Vec::new();
        for &bit in SUPPORTED {
            if !wanted(bit) || bit == A_TIME_ACCESS_SET || bit == A_TIME_MODIFY_SET {
                continue;
            }
            mask[(bit / 32) as usize] |= 1 << (bit % 32);
            let unit = st.as_ref().map_or(512, |st| {
                u64::from(if st.frsize == 0 { st.bsize } else { st.frsize })
            });
            match bit {
                A_SUPPORTED_ATTRS => put_bitmap(&mut v, &bits(SUPPORTED)),
                A_SUPPATTR_EXCLCREAT => put_bitmap(&mut v, &bits(EXCLCREAT)),
                A_TYPE => v.put_u32(ftype(attr.mode)),
                // FH4_PERSISTENT
                A_FH_EXPIRE_TYPE => v.put_u32(0),
                A_CHANGE => v.put_u64(change(attr)),
                A_SIZE => v.put_u64(attr.size),
                A_LINK_SUPPORT | A_SYMLINK_SUPPORT | A_UNIQUE_HANDLES | A_CANSETTIME
                | A_CASE_PRESERVING | A_CHOWN_RESTRICTED | A_HOMOGENEOUS | A_NO_TRUNC => {
                    v.put_bool(true);
                }
                A_NAMED_ATTR | A_CASE_INSENSITIVE => v.put_bool(false),
                A_FSID => {
                    v.put_u64(0x6675_7365);
                    v.put_u64(1);
                }
                A_LEASE_TIME => v.put_u32(LEASE_TIME),
                A_RDATTR_ERROR => v.put_u32(NFS4_OK),
                A_FILEHANDLE => self.put_handle(&mut v, node),
                A_FILEID | A_MOUNTED_ON_FILEID => v.put_u64(attr.ino),
                A_FILES_AVAIL | A_FILES_FREE => v.put_u64(st.as_ref().map_or(0, |st| st.ffree)),
                A_FILES_TOTAL => v.put_u64(st.as_ref().map_or(0, |st| st.files)),
                A_MAXFILESIZE => v.put_u64(i64::MAX as u64),
                A_MAXLINK => v.put_u32(u32::from(u16::MAX)),
                A_MAXNAME => v.put_u32(
                    st.as_ref()
                        .map_or(255, |st| if st.namelen == 0 { 255 } else { st.namelen }),
                ),
                A_MAXREAD | A_MAXWRITE => v.put_u64(MAX_IO.into()),
                A_MODE => v.put_u32(attr.mode & 0o7777),
                A_NUMLINKS => v.put_u32(attr.nlink),
                A_OWNER => v.put_opaque(attr.uid.to_string().as_bytes()),
                A_OWNER_GROUP => v.put_opaque(attr.gid.to_string().as_bytes()),
                A_RAWDEV => {
                    let rdev = attr.rdev as libc::dev_t;
                    v.put_u32(libc::major(rdev) as u32);
                    v.put_u32(libc::minor(rdev) as u32);
                }
                A_SPACE_AVAIL => {
                    v.put_u64(st.as_ref().map_or(0, |st| st.bavail.saturating_mul(unit)))
                }
                A_SPACE_FREE => {
                    v.put_u64(st.as_ref().map_or(0, |st| st.bfree.saturating_mul(unit)))
                }
                A_SPACE_TOTAL => {
                    v.put_u64(st.as_ref().map_or(0, |st| st.blocks.saturating_mul(unit)))
                }
                A_SPACE_USED => v.put_u64(attr.blocks.saturating_mul(512)),
                A_TIME_ACCESS => put_time(&mut v, attr.atime, attr.atimensec),
                A_TIME_DELTA => put_time(&mut v, 0, 1),
                A_TIME_METADATA => put_time(&mut v, attr.ctime, attr.ctimensec),
                A_TIME_MODIFY => put_time(&mut v, attr.mtime, attr.mtimensec),
                _ => unreachable!("every supported attribute is encoded"),
            }
        }
        put_bitmap(out, &mask);
        out.put_opaque(&v);
        Ok(())
    }

    /// The open behind a stateid, which must be of `node`; None for the special stateids, which
    /// use a handle kept here
    fn open_of(&self, id: Option<u64>, node: u64) -> Result<Option<(u64, i32)>> {
        let Some(id) = id else {
            return Ok(None);
        };
        let state = self.state.lock();
        let open_id = state.locks.get(&id).map_or(id, |lock| lock.open);
        let open = state
            .opens
            .get(&open_id)
            .filter(|open| open.node == node)
            .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
        Ok(Some((open.fh, open.flags)))
    }

    /// Syncs a file through each handle opened to write it, which is where a filesystem may
    /// hold what was written; or through one kept here, for writes made without an open
    fn commit(&self, node: u64) -> Result {
        let writable: Vec<u64> = self
            .state
            .lock()
            .opens
            .values()
            .filter(|open| open.node == node && open.flags & libc::O_ACCMODE != libc::O_RDONLY)
            .map(|open| open.fh)
            .collect();
        for fh in &writable {
            self.fuse.fsync_with(node, *fh)?;
        }
        if writable.is_empty() {
            self.fuse.fsync(node)?;
        }
        Ok(())
    }

    fn read(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, c: &Ctx) -> Result {
        let node = c.file()?;
        let id = c.stateid(a)?;
        let offset = a.u64()?;
        let count = a.u32()?.min(MAX_IO);
        let (data, eof) = match self.open_of(id, node)? {
            Some((fh, flags)) if flags & libc::O_ACCMODE != libc::O_WRONLY => {
                self.fuse.read_with(node, fh, flags, offset, count)?
            }
            _ => self.fuse.read(node, offset, count)?,
        };
        out.put_bool(eof);
        out.put_opaque(&data);
        Ok(())
    }

    fn write(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, c: &Ctx) -> Result {
        let node = c.file()?;
        let id = c.stateid(a)?;
        let offset = a.u64()?;
        let stable = a.u32()?;
        let data = a.opaque()?;
        let through = match self.open_of(id, node)? {
            Some((fh, flags)) if flags & libc::O_ACCMODE != libc::O_RDONLY => {
                self.fuse.write_with(node, fh, flags, offset, data)?;
                Some(fh)
            }
            _ => {
                self.fuse.write(node, offset, data)?;
                None
            }
        };
        // UNSTABLE4, or FILE_SYNC4 once the filesystem has synced what was written, through
        // the handle it was written through
        let committed = if stable == 0 {
            0
        } else {
            match through {
                Some(fh) => self.fuse.fsync_with(node, fh)?,
                None => self.fuse.fsync(node)?,
            }
            2
        };
        out.put_u32(data.len() as u32);
        out.put_u32(committed);
        out.put_fixed(&self.verifier);
        Ok(())
    }

    fn create(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, c: &mut Ctx) -> Result {
        let kind = a.u32()?;
        let target = if kind == NF4LNK {
            Some(a.opaque()?)
        } else {
            None
        };
        let rdev = if kind == NF4BLK || kind == NF4CHR {
            let (major, minor) = (a.u32()?, a.u32()?);
            // u32 on Linux, i32 on macOS
            libc::makedev(major as _, minor as _) as u32
        } else {
            0
        };
        let name = name4(a.opaque()?, Name::Create)?;
        let attrs = settable(a)?;
        let dir = c.file()?;
        let mode = attrs
            .sattr
            .mode
            .unwrap_or(if kind == NF4DIR { 0o755 } else { 0o644 })
            & 0o7777;
        let entry = match kind {
            NF4DIR => {
                let arg = fuse_mkdir_in { mode, umask: 0 };
                self.fuse
                    .make(fuse_opcode::FUSE_MKDIR, dir, &[arg.as_bytes(), name, b"\0"])?
            }
            NF4LNK => self.fuse.make(
                fuse_opcode::FUSE_SYMLINK,
                dir,
                &[name, b"\0", target.unwrap_or_default(), b"\0"],
            )?,
            NF4BLK | NF4CHR | NF4SOCK | NF4FIFO => {
                let kind_bits = match kind {
                    NF4BLK => 0o060000,
                    NF4CHR => 0o020000,
                    NF4SOCK => 0o140000,
                    _ => 0o010000,
                };
                self.fuse.mknod(dir, name, kind_bits | mode, rdev)?
            }
            // Regular files are made by OPEN
            _ => return Err(Error::Status(NFS4ERR_BADTYPE)),
        };
        if kind != NF4LNK {
            if let Some(arg) = setattr_in(&attrs.sattr, true) {
                self.fuse.setattr(entry.nodeid, &arg)?;
            }
        }
        c.current = Some(entry.nodeid);
        put_change_info(out);
        put_bitmap(out, &attrs.mask);
        Ok(())
    }

    fn readdir(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, dir: u64) -> Result {
        let cookie = a.u64()?;
        a.fixed(8)?;
        // dircount is a hint; maxcount bounds the reply
        a.u32()?;
        let maxcount = a.u32()? as usize;
        let request = bitmap(a)?;
        out.put_fixed(&[0; 8]);
        if dir == PSEUDO {
            // The export is not listed: it is looked up by name
            out.put_bool(false);
            out.put_bool(true);
            return Ok(());
        }
        // Cookies 1 and 2 are reserved, so FUSE offsets are shifted past them
        let offset = match cookie {
            0 => 0,
            1 | 2 => return Err(Error::Status(NFS4ERR_BAD_COOKIE)),
            cookie => cookie - 2,
        };
        // status, verifier, the list's end and eof
        let fixed = 4 + 8 + 4 + 4;
        let mut estimate = fixed;
        // NFSv4 lists neither "." nor "..", which clients make up themselves
        let dots = |name: &[u8]| name == b"." || name == b"..";
        let (entries, mut eof) = self.fuse.read_dir(dir, offset, |name| {
            if dots(name) {
                return true;
            }
            // Room for the name and its attributes, to stop listing early
            estimate += 4 + 8 + 4 + name.len().next_multiple_of(4) + 200;
            estimate <= maxcount
        })?;
        let start = out.len();
        let mut listed = 0;
        let started = Instant::now();
        for DirEntry { name, cookie, .. } in &entries {
            if dots(name) {
                continue;
            }
            // Looking each entry up may take long: the client asks again for the rest
            if listed > 0 && started.elapsed() > READDIR_BUDGET {
                eof = false;
                break;
            }
            let mut entry = Vec::new();
            entry.put_bool(true);
            entry.put_u64(cookie.wrapping_add(2));
            entry.put_opaque(name);
            match self.fuse.lookup(dir, name) {
                Ok(found) => self.put_fattr_of(&mut entry, found.nodeid, &found.attr, &request)?,
                // Gone since it was listed
                Err(_) => continue,
            }
            if fixed + (out.len() - start) + entry.len() > maxcount {
                eof = false;
                break;
            }
            out.extend_from_slice(&entry);
            listed += 1;
        }
        if listed == 0 && !eof {
            return Err(Error::Status(NFS4ERR_TOOSMALL));
        }
        out.put_bool(false);
        out.put_bool(eof);
        Ok(())
    }

    fn exchange_id(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let verifier: [u8; 8] = a.fixed(8)?.try_into().expect("8 bytes");
        let owner = a.opaque()?.to_vec();
        let flags = a.u32()?;
        // SP4_NONE, or SP4_MACH_CRED, agreed to with nothing enforced: AUTH_SYS proves nothing
        let protect = a.u32()?;
        match protect {
            0 => {}
            1 => {
                bitmap(a)?;
                bitmap(a)?;
            }
            _ => return Err(Error::Status(NFS4ERR_NOTSUPP)),
        }
        // The client's implementation, if it says
        match a.u32()? {
            0 => {}
            1 => {
                a.opaque()?;
                a.opaque()?;
                a.u64()?;
                a.u32()?;
            }
            _ => return Err(Error::Garbage),
        }
        let update = flags & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A != 0;
        let (clientid, released) = {
            let mut state = self.state.lock();
            let known = state
                .clients
                .iter()
                .find(|(_, client)| client.owner == owner)
                .map(|(id, client)| (*id, client.verifier == verifier));
            match known {
                Some((id, true)) => (id, Vec::new()),
                // Once mounted, the server is the mount's: another client, or one claiming to
                // have restarted, which would drop what it holds, may be another local user
                _ if self.sealed.load(Ordering::SeqCst) => {
                    return Err(Error::Status(NFS4ERR_PERM));
                }
                Some((_, false)) if update => return Err(Error::Status(NFS4ERR_NOT_SAME)),
                None if update => return Err(Error::Status(NFS4ERR_NOENT)),
                None if state.clients.len() >= MAX_CLIENTS => {
                    return Err(Error::Status(NFS4ERR_DELAY));
                }
                known => {
                    // A new client, or one that has restarted and so holds nothing any more
                    let released = known.map_or_else(Vec::new, |(id, _)| state.drop_client(id));
                    // Random, as CREATE_SESSION answers whoever names it
                    let id = u64::from_be_bytes(random()).max(1);
                    state.clients.insert(
                        id,
                        Client {
                            owner,
                            verifier,
                            confirmed: false,
                            sequence: 1,
                            created: None,
                        },
                    );
                    (id, released)
                }
            }
        };
        self.release(released);
        let state = self.state.lock();
        let client = state
            .clients
            .get(&clientid)
            .ok_or(Error::Status(NFS4ERR_STALE_CLIENTID))?;
        out.put_u64(clientid);
        out.put_u32(client.sequence);
        let confirmed = if client.confirmed {
            EXCHGID4_FLAG_CONFIRMED_R
        } else {
            0
        };
        out.put_u32(EXCHGID4_FLAG_USE_NON_PNFS | confirmed);
        out.put_u32(protect);
        if protect == 1 {
            put_bitmap(out, &[0; 3]);
            put_bitmap(out, &[0; 3]);
        }
        // server_owner4 and server scope: this server, which shares nothing with any other
        out.put_u64(0);
        out.put_opaque(&self.verifier);
        out.put_opaque(&self.verifier);
        // No implementation id
        out.put_u32(0);
        Ok(())
    }

    fn create_session(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let clientid = a.u64()?;
        let sequence = a.u32()?;
        let flags = a.u32()?;
        let fore = channel_attrs(a)?;
        let back = channel_attrs(a)?;
        // The callback program and its security, unused: no callback is ever made
        a.u32()?;
        for _ in 0..a.u32()? {
            callback_sec_parms(a)?;
        }
        let mut state = self.state.lock();
        {
            let client = state
                .clients
                .get_mut(&clientid)
                .ok_or(Error::Status(NFS4ERR_STALE_CLIENTID))?;
            // A retransmission, answered as before
            if sequence == client.sequence.wrapping_sub(1) {
                if let Some(reply) = &client.created {
                    out.extend_from_slice(reply);
                    return Ok(());
                }
            }
            if sequence != client.sequence {
                return Err(Error::Status(NFS4ERR_SEQ_MISORDERED));
            }
        }
        if state.sessions.len() >= MAX_SESSIONS {
            return Err(Error::Status(NFS4ERR_NOSPC));
        }
        if let Some(client) = state.clients.get_mut(&clientid) {
            client.sequence = client.sequence.wrapping_add(1);
            client.confirmed = true;
        }
        let mut id = [0; 16];
        // Random, as SEQUENCE answers whoever names it, with the replies it has kept
        id.copy_from_slice(&random::<16>());
        let max = MAX_RECORD as u32;
        // No header padding, and no more than this server takes
        let fore = [
            0,
            fore[1].min(max),
            fore[2].min(max),
            fore[3].min(max),
            fore[4].min(MAX_OPS),
            fore[5].clamp(1, MAX_SLOTS),
        ];
        let mut reply = Vec::new();
        reply.put_fixed(&id);
        reply.put_u32(sequence);
        // Not persistent, nor RDMA. A backchannel is accepted, though never called
        reply.put_u32(flags & CREATE_SESSION4_FLAG_CONN_BACK_CHAN);
        put_channel_attrs(&mut reply, &fore);
        put_channel_attrs(&mut reply, &back);
        if let Some(client) = state.clients.get_mut(&clientid) {
            client.created = Some(reply.clone());
        }
        state.sessions.insert(
            id,
            Session {
                clientid,
                slots: vec![Slot::default(); fore[5] as usize],
                max_ops: fore[4],
                max_response: fore[2] as usize,
                max_cached: fore[3] as usize,
            },
        );
        out.extend_from_slice(&reply);
        Ok(())
    }

    /// Releases the FUSE handles of opens no client holds any more
    fn release(&self, opens: Vec<Open>) {
        for open in opens {
            self.fuse.close_file(open.node, open.fh, open.flags);
        }
    }

    fn open(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, c: &mut Ctx) -> Result {
        a.u32()?;
        // The access asked for, without the delegations it may want
        let access = a.u32()? & 3;
        // share_deny: no share reservations are kept
        a.u32()?;
        let clientid = c.client(a.u64()?);
        let owner = a.opaque()?.to_vec();
        // UNCHECKED4, GUARDED4, EXCLUSIVE4 or EXCLUSIVE4_1, with the attributes to create with.
        // The verifiers are not kept: a retransmission whose reply was not cached fails
        let create = match a.u32()? {
            0 => None,
            1 => Some(match a.u32()? {
                mode @ (0 | 1) => (mode, settable(a)?),
                2 => {
                    a.fixed(8)?;
                    (2, Settable::default())
                }
                3 => {
                    a.fixed(8)?;
                    (3, settable(a)?)
                }
                _ => return Err(Error::Garbage),
            }),
            _ => return Err(Error::Garbage),
        };
        // A name in the current directory, or None for the current file
        let name = match a.u32()? {
            // CLAIM_NULL
            0 => Some(name4(a.opaque()?, Name::Create)?),
            // CLAIM_PREVIOUS: there is no grace period to reclaim in
            1 => {
                a.u32()?;
                return Err(Error::Status(NFS4ERR_NO_GRACE));
            }
            // CLAIM_FH
            4 => None,
            // Claims of delegations, of which there are none
            2 | 5 => {
                c.stateid(a)?;
                return Err(Error::Status(NFS4ERR_BAD_STATEID));
            }
            3 | 6 => return Err(Error::Status(NFS4ERR_NOTSUPP)),
            _ => return Err(Error::Garbage),
        };
        if access == 0 {
            return Err(Error::Status(NFS4ERR_INVAL));
        }
        if self.read_only && (create.is_some() || access & 2 != 0) {
            return Err(Error::Status(NFS4ERR_ROFS));
        }
        let current = c.file()?;
        if !self.state.lock().clients.contains_key(&clientid) {
            return Err(Error::Status(NFS4ERR_STALE_CLIENTID));
        }
        let flags = match access {
            1 => libc::O_RDONLY,
            2 => libc::O_WRONLY,
            _ => libc::O_RDWR,
        };
        let found = match name {
            Some(name) => self
                .fuse
                .lookup(current, name)
                .map(|entry| (entry.nodeid, entry.attr)),
            None => self.fuse.getattr(current).map(|attr| (current, attr)),
        };
        // The file, and a handle already opened for it, as creating it opens one
        let (node, opened, attrset) = match (found, &create, name) {
            (Ok(_), Some((1..=3, _)), _) => return Err(Error::Status(NFS4ERR_EXIST)),
            (Ok((node, attr)), _, _) => {
                match attr.mode & S_IFMT {
                    S_IFREG => {}
                    S_IFDIR => return Err(Error::Status(NFS4ERR_ISDIR)),
                    0o120000 => return Err(Error::Status(NFS4ERR_SYMLINK)),
                    _ => return Err(Error::Status(NFS4ERR_INVAL)),
                }
                let mut attrset = [0; 3];
                if let Some((_, attrs)) = &create {
                    // An UNCHECKED4 create of what exists: only its size is set
                    if let Some(size) = attrs.sattr.size {
                        let sattr = Sattr {
                            size: Some(size),
                            ..Sattr::default()
                        };
                        if let Some(arg) = setattr_in(&sattr, false) {
                            self.fuse.setattr(node, &arg)?;
                        }
                        attrset[0] |= 1 << A_SIZE;
                    }
                }
                (node, None, attrset)
            }
            (Err(libc::ENOENT), Some((how, attrs)), Some(name)) => {
                let mode = attrs.sattr.mode.unwrap_or(0o644);
                let (entry, opened) = self.fuse.create_open(current, name, mode, *how != 0)?;
                if let Some(arg) = setattr_in(&attrs.sattr, true) {
                    self.fuse.setattr(entry.nodeid, &arg)?;
                }
                (entry.nodeid, opened, attrs.mask)
            }
            (Err(errno), _, _) => return Err(Error::Errno(errno)),
        };
        // Opens are told apart by their access alone, not by O_CREAT and the like
        let opened = opened.map(|(fh, flags)| (fh, flags & libc::O_ACCMODE));
        let key = (clientid, owner);
        let existing = {
            let state = self.state.lock();
            state
                .opens
                .iter()
                .find(|(_, open)| open.node == node && open.owner == key)
                .map(|(id, open)| (*id, open.flags))
        };
        let union = |old: i32| {
            if old == flags || old == libc::O_RDWR {
                old
            } else {
                libc::O_RDWR
            }
        };
        let id = match existing {
            Some((id, old)) if union(old) == old => {
                if let Some((fh, flags)) = opened {
                    self.fuse.close_file(node, fh, flags);
                }
                let mut state = self.state.lock();
                let open = state
                    .opens
                    .get_mut(&id)
                    .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
                open.seqid += 1;
                id
            }
            Some((id, old)) => {
                // An upgrade: a handle for both, in place of the one there was
                let (new_fh, new_flags) = match opened {
                    Some(opened) if opened.1 == libc::O_RDWR => opened,
                    _ => (self.fuse.open_file(node, union(old))?, union(old)),
                };
                let mut state = self.state.lock();
                let open = state
                    .opens
                    .get_mut(&id)
                    .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
                let (old_fh, old_flags) = (open.fh, open.flags);
                open.fh = new_fh;
                open.flags = new_flags;
                open.seqid += 1;
                drop(state);
                self.fuse.close_file(node, old_fh, old_flags);
                id
            }
            None => {
                let (fh_new, flags_new) = match opened {
                    Some(opened) => opened,
                    None => (self.fuse.open_file(node, flags)?, flags),
                };
                let mut state = self.state.lock();
                // Another OPEN by the owner may have made one meanwhile: that one is kept
                let raced = state
                    .opens
                    .iter_mut()
                    .find(|(_, open)| open.node == node && open.owner == key)
                    .map(|(id, open)| {
                        open.seqid += 1;
                        *id
                    });
                match raced {
                    Some(id) => {
                        drop(state);
                        self.fuse.close_file(node, fh_new, flags_new);
                        id
                    }
                    None => {
                        let id = state.new_id();
                        state.opens.insert(
                            id,
                            Open {
                                node,
                                fh: fh_new,
                                flags: flags_new,
                                owner: key.clone(),
                                seqid: 1,
                            },
                        );
                        id
                    }
                }
            }
        };
        let seqid = self
            .state
            .lock()
            .opens
            .get(&id)
            .map_or(1, |open| open.seqid);
        c.current = Some(node);
        c.stateid = Some(id);
        put_stateid(out, seqid, id);
        put_change_info(out);
        // OPEN4_RESULT_LOCKTYPE_POSIX
        out.put_u32(4);
        put_bitmap(out, &attrset);
        // OPEN_DELEGATE_NONE
        out.put_u32(0);
        Ok(())
    }

    fn lock(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, c: &mut Ctx) -> Result {
        let locktype = a.u32()?;
        a.bool()?;
        let offset = a.u64()?;
        let length = a.u64()?;
        let lock_id = if a.bool()? {
            // A new lock-owner, for an open
            a.u32()?;
            let open_id = c.stateid(a)?.ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
            a.u32()?;
            let clientid = c.client(a.u64()?);
            let owner = a.opaque()?;
            let mut state = self.state.lock();
            if !state.opens.contains_key(&open_id) {
                return Err(Error::Status(NFS4ERR_BAD_STATEID));
            }
            let owner = state.lock_owner(clientid, owner);
            let existing = state
                .locks
                .iter()
                .find(|(_, lock)| lock.open == open_id && lock.owner == owner)
                .map(|(id, _)| *id);
            match existing {
                Some(id) => id,
                None => {
                    let id = state.new_id();
                    state.locks.insert(
                        id,
                        LockState {
                            open: open_id,
                            owner,
                            seqid: 0,
                        },
                    );
                    id
                }
            }
        } else {
            let id = c.stateid(a)?.ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
            a.u32()?;
            id
        };
        let (node, fh, owner) = self.lock_target(lock_id)?;
        let (start, end) = range(offset, length)?;
        // READ_LT and READW_LT; the others are write locks. Blocking ones are not waited for
        let write = !matches!(locktype, 1 | 3);
        self.set_lock(node, fh, owner, start, end, Some(write))?;
        let mut state = self.state.lock();
        let lock = state
            .locks
            .get_mut(&lock_id)
            .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
        lock.seqid += 1;
        put_stateid(out, lock.seqid, lock_id);
        c.stateid = Some(lock_id);
        Ok(())
    }

    fn lockt(&self, a: &mut Reader<'_>, c: &Ctx) -> Result {
        let node = c.file()?;
        let locktype = a.u32()?;
        let offset = a.u64()?;
        let length = a.u64()?;
        let clientid = c.client(a.u64()?);
        let owner = a.opaque()?;
        let owner = self.state.lock().lock_owner(clientid, owner);
        let (start, end) = range(offset, length)?;
        let write = !matches!(locktype, 1 | 3);
        if !self.local_locks.load(Ordering::Relaxed) {
            let typ = if write { F_WRLCK } else { F_RDLCK };
            match self.fuse.getlk(node, None, owner, start, end, typ) {
                Ok(lk) if lk.typ == F_UNLCK => return Ok(()),
                Ok(lk) => {
                    return Err(Error::Denied(denied(
                        lk.start,
                        lk.end,
                        lk.typ == F_WRLCK,
                        0,
                    )));
                }
                Err(libc::ENOSYS) => {
                    // Locks are kept here only if setlk is missing too, which unlocking
                    // nothing finds out without changing any lock
                    match self.fuse.setlk(node, 0, owner, start, end, F_UNLCK) {
                        Err(libc::ENOSYS) => self.local_locks.store(true, Ordering::Relaxed),
                        _ => return Err(Error::Status(NFS4ERR_NOTSUPP)),
                    }
                }
                Err(errno) => return Err(Error::Errno(errno)),
            }
        }
        let state = self.state.lock();
        match conflict(
            state.ranges.get(&node).map_or(&[][..], Vec::as_slice),
            owner,
            start,
            end,
            write,
        ) {
            Some(r) => Err(Error::Denied(denied(r.start, r.end, r.write, r.owner))),
            None => Ok(()),
        }
    }

    fn locku(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, c: &mut Ctx) -> Result {
        // The lock type and seqid, which 4.1 does not check
        a.u32()?;
        a.u32()?;
        let lock_id = c.stateid(a)?.ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
        let offset = a.u64()?;
        let length = a.u64()?;
        let (node, fh, owner) = self.lock_target(lock_id)?;
        let (start, end) = range(offset, length)?;
        self.set_lock(node, fh, owner, start, end, None)?;
        let mut state = self.state.lock();
        let lock = state
            .locks
            .get_mut(&lock_id)
            .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
        lock.seqid += 1;
        put_stateid(out, lock.seqid, lock_id);
        c.stateid = Some(lock_id);
        Ok(())
    }

    /// The node, FUSE handle and FUSE lock owner of a lock stateid
    fn lock_target(&self, lock_id: u64) -> Result<(u64, u64, u64)> {
        let state = self.state.lock();
        let lock = state
            .locks
            .get(&lock_id)
            .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
        let open = state
            .opens
            .get(&lock.open)
            .ok_or(Error::Status(NFS4ERR_BAD_STATEID))?;
        Ok((open.node, open.fh, lock.owner))
    }

    /// Takes a lock (`write` Some), or drops one, through the filesystem or the table here
    fn set_lock(
        &self,
        node: u64,
        fh: u64,
        owner: u64,
        start: u64,
        end: u64,
        write: Option<bool>,
    ) -> Result {
        if !self.local_locks.load(Ordering::Relaxed) {
            let typ = match write {
                None => F_UNLCK,
                Some(true) => F_WRLCK,
                Some(false) => F_RDLCK,
            };
            match self.fuse.setlk(node, fh, owner, start, end, typ) {
                Ok(()) => return Ok(()),
                Err(libc::EAGAIN | libc::EACCES) => {
                    // Who holds it, if the filesystem says; else the range asked for
                    let lk = self.fuse.getlk(node, Some(fh), owner, start, end, typ);
                    let (start, end, write) = lk.map_or((start, end, true), |lk| {
                        (lk.start, lk.end, lk.typ == F_WRLCK)
                    });
                    return Err(Error::Denied(denied(start, end, write, 0)));
                }
                Err(libc::ENOSYS) => self.local_locks.store(true, Ordering::Relaxed),
                Err(errno) => return Err(Error::Errno(errno)),
            }
        }
        let mut state = self.state.lock();
        let ranges = state.ranges.entry(node).or_default();
        if let Some(write) = write {
            if let Some(r) = conflict(ranges, owner, start, end, write) {
                return Err(Error::Denied(denied(r.start, r.end, r.write, r.owner)));
            }
        }
        unlock_range(ranges, owner, start, end);
        if let Some(write) = write {
            ranges.push(Range {
                owner,
                start,
                end,
                write,
            });
        }
        Ok(())
    }
}

/// A name from a request (a component4), checked as the kernel would before passing it on.
/// NFSv4 has no "." or ".." entries to look up; as other names, they get what POSIX says. A
/// REMOVE's "." and ".." are directories
fn name4(name: &[u8], name_use: Name) -> Result<&[u8]> {
    if name.is_empty() {
        return Err(Error::Status(NFS4ERR_INVAL));
    }
    let dots = name == b"." || name == b"..";
    if name.contains(&b'/') || name.contains(&0) || (dots && name_use == Name::Lookup) {
        return Err(Error::Status(NFS4ERR_BADNAME));
    }
    name_arg(name, name_use).map_err(Error::Errno)
}

/// Bytes from the system's random source
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    // getentropy fills up to 256 bytes, and fails only for more
    // SAFETY: the buffer is N bytes long
    let filled = unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), N) };
    assert_eq!(filled, 0, "getentropy failed");
    bytes
}

/// Attributes a client asks to set, and the mask of those it gave
#[derive(Debug, Default)]
struct Settable {
    sattr: Sattr,
    mask: Bitmap,
}

/// Decodes an fattr4 of attributes to set. Those with no counterpart in FUSE but harmless to
/// drop, such as the archive bit, are taken and dropped
fn settable(a: &mut Reader<'_>) -> Result<Settable> {
    let mask = bitmap(a)?;
    let values = a.opaque()?;
    let r = &mut Reader::new(values);
    let mut sattr = Sattr::default();
    for bit in 0..96 {
        if !is_set(&mask, bit) {
            continue;
        }
        match bit {
            A_SIZE => sattr.size = Some(r.u64()?),
            A_MODE => sattr.mode = Some(r.u32()?),
            A_OWNER => sattr.uid = Some(owner(r.opaque()?, false)?),
            A_OWNER_GROUP => sattr.gid = Some(owner(r.opaque()?, true)?),
            A_TIME_ACCESS_SET => sattr.atime = settime(r)?,
            A_TIME_MODIFY_SET => sattr.mtime = settime(r)?,
            A_ARCHIVE | A_HIDDEN | A_SYSTEM => {
                r.bool()?;
            }
            A_TIME_CREATE => {
                r.u64()?;
                r.u32()?;
            }
            _ => return Err(Error::Status(NFS4ERR_ATTRNOTSUPP)),
        }
    }
    Ok(Settable { sattr, mask })
}

/// An owner or group: numeric, as this server sends them, or a name the host's user database
/// knows, as macOS sends root, either perhaps with a domain
fn owner(name: &[u8], group: bool) -> Result<u32> {
    let name = std::str::from_utf8(name).map_err(|_| Error::Status(NFS4ERR_BADOWNER))?;
    let name = name.split('@').next().unwrap_or_default();
    if let Ok(id) = name.parse() {
        return Ok(id);
    }
    let id = if group {
        nix::unistd::Group::from_name(name)
            .ok()
            .flatten()
            .map(|g| g.gid.as_raw())
    } else {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
    };
    id.ok_or(Error::Status(NFS4ERR_BADOWNER))
}

fn settime(r: &mut Reader<'_>) -> Result<SetTime> {
    Ok(match r.u32()? {
        // SET_TO_SERVER_TIME4
        0 => SetTime::Now,
        _ => {
            let seconds = r.u64()? as i64;
            let nanoseconds = r.u32()?;
            SetTime::At(seconds.clamp(0, u32::MAX.into()) as u32, nanoseconds)
        }
    })
}

fn bitmap(a: &mut Reader<'_>) -> Result<Bitmap> {
    let words = a.u32()?;
    let mut mask = [0; 3];
    for i in 0..words {
        let word = a.u32()?;
        if let Some(slot) = mask.get_mut(i as usize) {
            *slot = word;
        }
    }
    Ok(mask)
}

fn put_bitmap(out: &mut Vec<u8>, mask: &Bitmap) {
    let words = mask
        .iter()
        .rposition(|word| *word != 0)
        .map_or(0, |i| i + 1);
    out.put_u32(words as u32);
    for word in &mask[..words] {
        out.put_u32(*word);
    }
}

fn bits(attrs: &[u32]) -> Bitmap {
    let mut mask = [0; 3];
    for &bit in attrs {
        mask[(bit / 32) as usize] |= 1 << (bit % 32);
    }
    mask
}

fn is_set(mask: &Bitmap, bit: u32) -> bool {
    mask.get((bit / 32) as usize)
        .is_some_and(|word| word & (1 << (bit % 32)) != 0)
}

/// The values of a channel_attrs4 but its RDMA one, which is dropped
fn channel_attrs(a: &mut Reader<'_>) -> Result<[u32; 6]> {
    let mut attrs = [0; 6];
    for value in &mut attrs {
        *value = a.u32()?;
    }
    match a.u32()? {
        0 => {}
        1 => {
            a.u32()?;
        }
        _ => return Err(Error::Garbage),
    }
    Ok(attrs)
}

fn put_channel_attrs(out: &mut Vec<u8>, attrs: &[u32; 6]) {
    for value in attrs {
        out.put_u32(*value);
    }
    // No RDMA
    out.put_u32(0);
}

/// Decodes a callback_sec_parms4, which is not used
fn callback_sec_parms(a: &mut Reader<'_>) -> Result {
    match a.u32()? {
        // AUTH_NONE
        0 => {}
        // AUTH_SYS: stamp, machine name, uid, gid and groups
        1 => {
            a.u32()?;
            a.opaque()?;
            a.u32()?;
            a.u32()?;
            for _ in 0..a.u32()? {
                a.u32()?;
            }
        }
        // RPCSEC_GSS
        6 => {
            a.u32()?;
            a.opaque()?;
            a.opaque()?;
        }
        _ => return Err(Error::Garbage),
    }
    Ok(())
}

fn put_stateid(out: &mut Vec<u8>, seqid: u32, id: u64) {
    out.put_u32(seqid);
    out.put_fixed(&[&id.to_be_bytes()[..], &[0; 4]].concat());
}

/// change_info4 that says nothing: not atomic, so the client looks again
fn put_change_info(out: &mut Vec<u8>) {
    out.put_bool(false);
    out.put_u64(0);
    out.put_u64(0);
}

fn put_time(out: &mut Vec<u8>, seconds: i64, nanoseconds: u32) {
    out.put_u64(seconds as u64);
    out.put_u32(nanoseconds);
}

fn ftype(mode: u32) -> u32 {
    match mode & S_IFMT {
        S_IFDIR => NF4DIR,
        S_IFREG => NF4REG,
        0o120000 => NF4LNK,
        0o060000 => NF4BLK,
        0o020000 => NF4CHR,
        0o140000 => NF4SOCK,
        0o010000 => NF4FIFO,
        _ => NF4REG,
    }
}

/// The change attribute: the later of the modification and change times, in nanoseconds
fn change(attr: &fuse_attr) -> u64 {
    let ns = |seconds: i64, nanoseconds: u32| {
        (seconds.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nanoseconds.into())
    };
    ns(attr.mtime, attr.mtimensec).max(ns(attr.ctime, attr.ctimensec))
}

/// A lock's range as FUSE gives it: from `offset`, inclusive of `end`; a length of all ones is
/// to the end of the file
fn range(offset: u64, length: u64) -> Result<(u64, u64)> {
    if length == 0 || offset > OFFSET_MAX {
        return Err(Error::Status(NFS4ERR_INVAL));
    }
    if length == u64::MAX {
        return Ok((offset, OFFSET_MAX));
    }
    let end = offset
        .checked_add(length - 1)
        .ok_or(Error::Status(NFS4ERR_LOCK_RANGE))?;
    // Past what FUSE's signed offsets reach: to the end, as all ones means
    Ok((offset, end.min(OFFSET_MAX)))
}

/// LOCK4denied: the conflicting lock, with an owner that is only an id
fn denied(start: u64, end: u64, write: bool, owner: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_u64(start);
    out.put_u64(if end >= i64::MAX as u64 {
        u64::MAX
    } else {
        end - start + 1
    });
    // WRITE_LT or READ_LT
    out.put_u32(if write { 2 } else { 1 });
    out.put_u64(0);
    out.put_opaque(&owner.to_be_bytes());
    out
}

/// The lock of another owner that `start..=end` would conflict with
fn conflict(ranges: &[Range], owner: u64, start: u64, end: u64, write: bool) -> Option<Range> {
    ranges
        .iter()
        .find(|r| r.owner != owner && r.start <= end && start <= r.end && (write || r.write))
        .copied()
}

/// Drops `owner`'s locks on `start..=end`, keeping what of them lies outside it
fn unlock_range(ranges: &mut Vec<Range>, owner: u64, start: u64, end: u64) {
    let mut kept = Vec::with_capacity(ranges.len());
    for r in ranges.drain(..) {
        if r.owner != owner || r.end < start || end < r.start {
            kept.push(r);
            continue;
        }
        if r.start < start {
            kept.push(Range {
                end: start - 1,
                ..r
            });
        }
        if end < r.end {
            kept.push(Range {
                start: end + 1,
                ..r
            });
        }
    }
    *ranges = kept;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lock_ranges() {
        let mut ranges = vec![Range {
            owner: 1,
            start: 0,
            end: 99,
            write: true,
        }];
        assert!(conflict(&ranges, 2, 50, 60, false).is_some());
        assert!(conflict(&ranges, 1, 50, 60, true).is_none());
        assert!(conflict(&ranges, 2, 100, 200, true).is_none());
        unlock_range(&mut ranges, 1, 40, 59);
        assert_eq!(
            ranges.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>(),
            [(0, 39), (60, 99)]
        );
        assert!(conflict(&ranges, 2, 40, 59, true).is_none());
        assert_eq!(range(10, u64::MAX).unwrap(), (10, i64::MAX as u64));
        assert_eq!(range(10, 5).unwrap(), (10, 14));
        assert!(range(10, 0).is_err());
    }
}
