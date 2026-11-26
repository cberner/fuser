//! SMB 2.1 (MS-SMB2), as far as a client needs it to mount and use one share: each command
//! answered with FUSE requests through the [`Client`].
//!
//! No SMB 1 beyond the multi-protocol NEGOTIATE that leads to SMB 2, and no SMB 3. There are
//! no oplocks, leases, durable handles, named streams, extended attributes, security
//! descriptors or change notifications; byte-range locks are granted without being kept.
//! Requests are answered one at a time, so credits are granted as asked.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::io::Read;
use std::sync::Arc;
use std::time::SystemTime;

use super::client::Client;
use super::client::Node;
use super::client::PathError;
use super::client::SetAttr;
use super::convert;
use super::convert::ErrorKind;
use super::crypto::hmac_sha256;
use super::ntlm;
use super::ntlm::Logon;
use super::ntlm::Step;
use super::wire::Put;
use super::wire::bytes_at;
use super::wire::from_utf16;
use super::wire::u8_at;
use super::wire::u16_at;
use super::wire::u32_at;
use super::wire::u64_at;
use super::wire::utf16;
use crate::Errno;
use crate::FileAttr;
use crate::FileType;
use crate::INodeNo;

/// The largest read, write or transaction, as one credit allows without LARGE_MTU
pub(crate) const MAX_IO: u32 = 64 * 1024;
const HEADER_LEN: usize = 64;
/// How much of a directory to ask for at a time
const READDIR_SIZE: u32 = 64 * 1024;
/// SMB carries no mode, so new files and directories get these
const NEW_FILE_MODE: u32 = 0o644;
const NEW_DIR_MODE: u32 = 0o755;

// Commands
const NEGOTIATE: u16 = 0;
const SESSION_SETUP: u16 = 1;
const LOGOFF: u16 = 2;
const TREE_CONNECT: u16 = 3;
const TREE_DISCONNECT: u16 = 4;
const CREATE: u16 = 5;
const CLOSE: u16 = 6;
const FLUSH: u16 = 7;
const READ: u16 = 8;
const WRITE: u16 = 9;
const LOCK: u16 = 10;
const CANCEL: u16 = 12;
const ECHO: u16 = 13;
const QUERY_DIRECTORY: u16 = 14;
const QUERY_INFO: u16 = 16;
const SET_INFO: u16 = 17;

// Header flags
const SERVER_TO_REDIR: u32 = 0x1;
const RELATED_OPERATIONS: u32 = 0x4;
const SIGNED: u32 = 0x8;

// NTSTATUS
const STATUS_SUCCESS: u32 = 0;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_QUOTA_EXCEEDED: u32 = 0xC000_0044;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_DISK_FULL: u32 = 0xC000_007F;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
const STATUS_NOT_SAME_DEVICE: u32 = 0xC000_00D4;
const STATUS_UNEXPECTED_IO_ERROR: u32 = 0xC000_00E9;
const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;

// Access mask bits
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const DELETE: u32 = 0x1_0000;
const MAXIMUM_ALLOWED: u32 = 0x200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

/// The one share, and what logs on to it
#[derive(Debug)]
pub(crate) struct Share {
    pub(crate) client: Arc<Client>,
    pub(crate) name: String,
    pub(crate) read_only: bool,
    pub(crate) user: String,
    pub(crate) nt_hash: [u8; 16],
    pub(crate) guid: [u8; 16],
}

/// Fills `buf` from the system's random source
pub(crate) fn random(buf: &mut [u8]) -> io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

#[derive(Debug, Default)]
struct Session {
    /// While logging on
    logon: Option<Logon>,
    key: Option<[u8; 16]>,
    /// Every response is signed
    signing: bool,
    trees: HashSet<u32>,
}

#[derive(Debug)]
struct Open {
    node: INodeNo,
    /// None for an open of the attributes only
    fh: Option<u64>,
    flags: i32,
    is_dir: bool,
    writable: bool,
    access: u32,
    /// From the share's root
    path: Vec<String>,
    delete_on_close: bool,
    /// What QUERY_DIRECTORY lists, and how far it has got
    listing: Option<(Vec<(String, FileAttr)>, usize)>,
    session: u64,
    tree: u32,
}

impl Open {
    /// The handle to give GETATTR and SETATTR, which take file handles only
    fn file_handle(&self) -> Option<u64> {
        self.fh.filter(|_| !self.is_dir)
    }
}

/// A request's header, with what it inherits from the one before in a related compound
#[derive(Debug, Clone, Copy)]
struct Header {
    command: u16,
    credit_charge: u16,
    credits: u16,
    flags: u32,
    message_id: u64,
    process_id: u32,
    tree_id: u32,
    session_id: u64,
}

/// Handler results: the status and body of a response, or an error status
type Reply = Result<(u32, Vec<u8>), u32>;

trait OrInvalid<T> {
    fn invalid(self) -> Result<T, u32>;
}

impl<T> OrInvalid<T> for Option<T> {
    fn invalid(self) -> Result<T, u32> {
        self.ok_or(STATUS_INVALID_PARAMETER)
    }
}

/// What a request in a compound leaves for the related ones after it
#[derive(Debug, Default, Clone, Copy)]
struct Chain {
    session_id: u64,
    tree_id: u32,
    file_id: Option<u64>,
    /// An error the related requests that follow fail with too
    failed: Option<u32>,
}

/// The state of one connection, whose messages are answered in turn
#[derive(Debug)]
pub(crate) struct Connection<'a> {
    share: &'a Share,
    /// Before NEGOTIATE, 0
    dialect: u16,
    client_requires_signing: bool,
    sessions: HashMap<u64, Session>,
    opens: HashMap<u64, Open>,
    next_id: u64,
}

impl<'a> Connection<'a> {
    pub(crate) fn new(share: &'a Share) -> Self {
        Connection {
            share,
            dialect: 0,
            client_requires_signing: false,
            sessions: HashMap::new(),
            opens: HashMap::new(),
            next_id: 1,
        }
    }

    fn client(&self) -> &Client {
        &self.share.client
    }

    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Answers one message, which may be a compound of requests. None ends the connection
    pub(crate) fn answer(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        if message.starts_with(b"\xffSMB") {
            return self.smb1_negotiate(message);
        }
        let mut out = Vec::new();
        // Where the response last added starts
        let mut last: Option<usize> = None;
        let mut chain = Chain::default();
        let mut offset = 0;
        loop {
            let rest = message.get(offset..)?;
            let next = u32_at(rest, 20)? as usize;
            let req = if next == 0 { rest } else { rest.get(..next)? };
            if !req.starts_with(b"\xfeSMB") || req.len() < HEADER_LEN {
                return None;
            }
            let mut h = Header {
                command: u16_at(req, 12)?,
                credit_charge: u16_at(req, 6)?,
                credits: u16_at(req, 14)?,
                flags: u32_at(req, 16)?,
                message_id: u64_at(req, 24)?,
                process_id: u32_at(req, 32)?,
                tree_id: u32_at(req, 36)?,
                session_id: u64_at(req, 40)?,
            };
            let related = h.flags & RELATED_OPERATIONS != 0;
            if related {
                h.session_id = chain.session_id;
                h.tree_id = chain.tree_id;
            } else {
                chain = Chain {
                    session_id: h.session_id,
                    tree_id: h.tree_id,
                    ..Chain::default()
                };
            }
            // CANCEL is not answered: nothing is pending to cancel
            if h.command != CANCEL {
                let result = match chain.failed {
                    Some(status) if related => Err(status),
                    _ => self.command(&h, req, &mut chain),
                };
                let (status, body) = match result {
                    Ok(reply) => reply,
                    Err(status) => (status, vec![9, 0, 0, 0, 0, 0, 0, 0, 0]),
                };
                if status & 0xC000_0000 == 0xC000_0000 && status != STATUS_MORE_PROCESSING_REQUIRED
                {
                    chain.failed = Some(status);
                }
                let start = match last {
                    // The previous response is followed by this one, 8-byte aligned
                    Some(previous) => {
                        let start = out.len().next_multiple_of(8);
                        out.resize(start, 0);
                        out.set_u32(previous + 20, (start - previous) as u32);
                        self.sign(&mut out, previous, start);
                        start
                    }
                    None => 0,
                };
                self.respond(&mut out, &h, &chain, status, &body);
                last = Some(start);
            }
            if next == 0 {
                break;
            }
            offset += next;
        }
        if let Some(last) = last {
            let end = out.len();
            self.sign(&mut out, last, end);
        }
        Some(out)
    }

    /// Signs the response at `out[start..end]`, if its session signs
    fn sign(&self, out: &mut [u8], start: usize, end: usize) {
        if u32_at(out, start + 16).is_some_and(|flags| flags & SIGNED == 0) {
            return;
        }
        let Some(key) = u64_at(out, start + 40)
            .and_then(|id| self.sessions.get(&id))
            .and_then(|session| session.key)
        else {
            return;
        };
        out[start + 48..start + 64].fill(0);
        let signature = hmac_sha256(&key, &[&out[start..end]]);
        out[start + 48..start + 64].copy_from_slice(&signature[..16]);
    }

    fn respond(&self, out: &mut Vec<u8>, h: &Header, chain: &Chain, status: u32, body: &[u8]) {
        // The session SESSION_SETUP sets up, or the request's
        let session_id = if h.command == SESSION_SETUP {
            chain.session_id
        } else {
            h.session_id
        };
        let signs = self
            .sessions
            .get(&session_id)
            .is_some_and(|s| s.key.is_some() && (s.signing || h.flags & SIGNED != 0));
        out.extend_from_slice(b"\xfeSMB");
        out.put_u16(HEADER_LEN as u16);
        out.put_u16(h.credit_charge);
        out.put_u32(status);
        out.put_u16(h.command);
        out.put_u16(h.credits.clamp(1, 256));
        out.put_u32(
            SERVER_TO_REDIR | (h.flags & RELATED_OPERATIONS) | if signs { SIGNED } else { 0 },
        );
        // NextCommand, set once a response follows
        out.put_u32(0);
        out.put_u64(h.message_id);
        out.put_u32(h.process_id);
        out.put_u32(if h.command == TREE_CONNECT {
            chain.tree_id
        } else {
            h.tree_id
        });
        out.put_u64(session_id);
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(body);
    }

    /// The multi-protocol NEGOTIATE of SMB 1, which a client may open with: answered with an
    /// SMB 2 NEGOTIATE response, after which it negotiates again in SMB 2
    fn smb1_negotiate(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        if u8_at(message, 4)? != 0x72 {
            return None;
        }
        let has = |dialect: &[u8]| message.windows(dialect.len()).any(|w| w == dialect);
        let dialect = if has(b"SMB 2.???") {
            0x02FF
        } else if has(b"SMB 2.002") {
            self.dialect = 0x0202;
            0x0202
        } else {
            return None;
        };
        let h = Header {
            command: NEGOTIATE,
            credit_charge: 0,
            credits: 1,
            flags: 0,
            message_id: 0,
            process_id: 0,
            tree_id: 0,
            session_id: 0,
        };
        let mut out = Vec::new();
        let body = self.negotiate_response(dialect);
        self.respond(&mut out, &h, &Chain::default(), STATUS_SUCCESS, &body);
        Some(out)
    }

    fn command(&mut self, h: &Header, req: &[u8], chain: &mut Chain) -> Reply {
        let body = &req[HEADER_LEN..];
        match h.command {
            NEGOTIATE => return self.negotiate(body),
            SESSION_SETUP => return self.session_setup(h, req, chain),
            ECHO => return Ok((STATUS_SUCCESS, vec![4, 0, 0, 0])),
            _ => {}
        }
        let in_tree = self
            .sessions
            .get(&h.session_id)
            .filter(|s| s.key.is_some())
            .ok_or(STATUS_USER_SESSION_DELETED)?
            .trees
            .contains(&h.tree_id);
        match h.command {
            LOGOFF => {
                self.close_where(|open| open.session == h.session_id);
                self.sessions.remove(&h.session_id);
                return Ok((STATUS_SUCCESS, vec![4, 0, 0, 0]));
            }
            TREE_CONNECT => return self.tree_connect(h, req, chain),
            _ => {}
        }
        if !in_tree {
            return Err(STATUS_NETWORK_NAME_DELETED);
        }
        // The open a request names: the one a CREATE before it in the compound made, for
        // the related requests after it
        let related_file = chain.file_id;
        let file_id = |at: usize| -> Result<u64, u32> {
            let id = bytes_at(body, at, 16).invalid()?;
            if id == [0xff; 16] {
                related_file.ok_or(STATUS_FILE_CLOSED)
            } else {
                u64_at(id, 0).invalid()
            }
        };
        match h.command {
            TREE_DISCONNECT => {
                self.close_where(|open| open.session == h.session_id && open.tree == h.tree_id);
                if let Some(session) = self.sessions.get_mut(&h.session_id) {
                    session.trees.remove(&h.tree_id);
                }
                Ok((STATUS_SUCCESS, vec![4, 0, 0, 0]))
            }
            CREATE => self.create(h, req, chain),
            CLOSE => self.close(file_id(8)?, body),
            FLUSH => {
                let open = self.open(file_id(8)?)?;
                if let Some(fh) = open.file_handle() {
                    self.client().fsync(open.node, fh).map_err(status)?;
                }
                Ok((STATUS_SUCCESS, vec![4, 0, 0, 0]))
            }
            READ => self.read(file_id(16)?, body),
            WRITE => self.write(file_id(16)?, req),
            // Granted, but not kept: smbfs makes do with local locks
            LOCK => Ok((STATUS_SUCCESS, vec![4, 0, 0, 0])),
            QUERY_DIRECTORY => self.query_directory(file_id(8)?, req),
            QUERY_INFO => self.query_info(file_id(24)?, body),
            SET_INFO => self.set_info(file_id(16)?, req),
            // IOCTL, CHANGE_NOTIFY and OPLOCK_BREAK: no FSCTLs, notifications or oplocks
            _ => Err(STATUS_NOT_SUPPORTED),
        }
    }

    fn negotiate(&mut self, body: &[u8]) -> Reply {
        let count = u16_at(body, 2).invalid()? as usize;
        let security_mode = u16_at(body, 4).invalid()?;
        let offered = (0..count)
            .map(|i| u16_at(body, 36 + 2 * i))
            .collect::<Option<Vec<u16>>>()
            .invalid()?;
        let dialect = [0x0210, 0x0202]
            .into_iter()
            .find(|d| offered.contains(d))
            .ok_or(STATUS_NOT_SUPPORTED)?;
        self.dialect = dialect;
        // SMB2_NEGOTIATE_SIGNING_REQUIRED
        self.client_requires_signing = security_mode & 0x2 != 0;
        Ok((STATUS_SUCCESS, self.negotiate_response(dialect)))
    }

    fn negotiate_response(&self, dialect: u16) -> Vec<u8> {
        let hint = ntlm::negotiate_hint();
        let mut b = Vec::new();
        b.put_u16(65);
        // SMB2_NEGOTIATE_SIGNING_ENABLED
        b.put_u16(0x1);
        b.put_u16(dialect);
        b.put_u16(0);
        b.extend_from_slice(&self.share.guid);
        // No capabilities: no DFS, leases or multi-credit requests
        b.put_u32(0);
        for _ in 0..3 {
            b.put_u32(MAX_IO);
        }
        b.put_u64(convert::filetime(SystemTime::now()));
        b.put_u64(0);
        b.put_u16((HEADER_LEN + 64) as u16);
        b.put_u16(hint.len() as u16);
        b.put_u32(0);
        b.extend_from_slice(&hint);
        b
    }

    fn session_setup(&mut self, h: &Header, req: &[u8], chain: &mut Chain) -> Reply {
        if self.dialect == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let body = &req[HEADER_LEN..];
        let security_mode = u8_at(body, 3).invalid()?;
        let blob = bytes_at(
            req,
            u16_at(body, 12).invalid()? as usize,
            u16_at(body, 14).invalid()? as usize,
        )
        .invalid()?;
        let id = if h.session_id == 0 {
            let id = self.new_id();
            self.sessions.insert(id, Session::default());
            id
        } else {
            h.session_id
        };
        chain.session_id = id;
        let mut challenge = [0; 8];
        random(&mut challenge).map_err(|_| STATUS_UNEXPECTED_IO_ERROR)?;
        let share = self.share;
        let client_requires_signing = self.client_requires_signing;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(STATUS_USER_SESSION_DELETED)?;
        let step = session.logon.get_or_insert_with(Logon::default).step(
            blob,
            &share.user,
            &share.nt_hash,
            challenge,
            convert::filetime(SystemTime::now()),
        );
        let (status, token) = match step {
            Some(Step::Continue(token)) => (STATUS_MORE_PROCESSING_REQUIRED, token),
            Some(Step::Done { session_key, token }) => {
                session.logon = None;
                session.key = Some(session_key);
                // SMB2_NEGOTIATE_SIGNING_REQUIRED, here or in NEGOTIATE
                session.signing = client_requires_signing || security_mode & 0x2 != 0;
                (STATUS_SUCCESS, token)
            }
            None => {
                self.sessions.remove(&id);
                return Err(STATUS_LOGON_FAILURE);
            }
        };
        let mut b = Vec::new();
        b.put_u16(9);
        // SessionFlags: neither guest nor anonymous
        b.put_u16(0);
        b.put_u16((HEADER_LEN + 8) as u16);
        b.put_u16(token.len() as u16);
        b.extend_from_slice(&token);
        Ok((status, b))
    }

    fn tree_connect(&mut self, h: &Header, req: &[u8], chain: &mut Chain) -> Reply {
        let body = &req[HEADER_LEN..];
        let path = bytes_at(
            req,
            u16_at(body, 4).invalid()? as usize,
            u16_at(body, 6).invalid()? as usize,
        )
        .and_then(from_utf16)
        .invalid()?;
        let name = path.rsplit('\\').next().unwrap_or_default();
        if !name.eq_ignore_ascii_case(&self.share.name) {
            return Err(STATUS_BAD_NETWORK_NAME);
        }
        let tree = self.new_id() as u32;
        if let Some(session) = self.sessions.get_mut(&h.session_id) {
            session.trees.insert(tree);
        }
        chain.tree_id = tree;
        let mut b = Vec::new();
        b.put_u16(16);
        // SMB2_SHARE_TYPE_DISK
        b.put_u8(1);
        b.put_u8(0);
        // No share flags or capabilities
        b.put_u32(0);
        b.put_u32(0);
        // MaximalAccess: all, or reading only
        b.put_u32(if self.share.read_only {
            0x0012_00A9
        } else {
            0x001F_01FF
        });
        Ok((STATUS_SUCCESS, b))
    }

    fn open(&self, id: u64) -> Result<&Open, u32> {
        self.opens.get(&id).ok_or(STATUS_FILE_CLOSED)
    }

    fn create(&mut self, h: &Header, req: &[u8], chain: &mut Chain) -> Reply {
        let body = &req[HEADER_LEN..];
        let access = u32_at(body, 24).invalid()?;
        let disposition = u32_at(body, 36).invalid()?;
        let options = u32_at(body, 40).invalid()?;
        let name = bytes_at(
            req,
            u16_at(body, 44).invalid()? as usize,
            u16_at(body, 46).invalid()? as usize,
        )
        .and_then(from_utf16)
        .ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let path = parse_path(&name)?;
        let read = access & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED) != 0;
        let write =
            access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL) != 0;
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let delete_on_close = options & FILE_DELETE_ON_CLOSE != 0;
        let creates = matches!(
            disposition,
            FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE
        );
        let truncates = matches!(
            disposition,
            FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE
        );
        if disposition > FILE_OVERWRITE_IF {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let read_only = self.share.read_only;
        if read_only && (write || truncates || delete_on_close || access & DELETE != 0) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let client = self.client();
        let components: Vec<&str> = path.iter().map(String::as_str).collect();
        let existing = match client.resolve(&components) {
            Ok(node) => Some(node),
            Err(PathError::Last(Errno::ENOENT)) => None,
            Err(err) => return Err(path_status(err)),
        };
        let mut flags = match (read, write) {
            (_, false) => libc::O_RDONLY,
            (false, true) => libc::O_WRONLY,
            (true, true) => libc::O_RDWR,
        };
        let (node, fh, action) = match existing {
            Some(_) if disposition == FILE_CREATE => return Err(STATUS_OBJECT_NAME_COLLISION),
            Some(mut node) => {
                let kind = node.attr.kind;
                if kind == FileType::Directory {
                    if options & FILE_NON_DIRECTORY_FILE != 0 || truncates {
                        return Err(STATUS_FILE_IS_A_DIRECTORY);
                    }
                } else if want_dir {
                    return Err(STATUS_NOT_A_DIRECTORY);
                }
                if truncates && !write {
                    // Overwriting needs write access to the data, whatever else was asked
                    flags = if read { libc::O_RDWR } else { libc::O_WRONLY };
                }
                let opened = match kind {
                    FileType::Directory => client.opendir(node.id),
                    FileType::RegularFile => client.open(node.id, flags),
                    // Symlinks and special files can be looked at, not read or written
                    _ if !write && !truncates => Err(Errno::EACCES),
                    _ => return Err(STATUS_ACCESS_DENIED),
                };
                let fh = match opened {
                    Ok(fh) => Some(fh),
                    // SMB cannot say whether an open is for the data or the attributes only,
                    // as for a stat. Allow it, as an open that fails what needs the data
                    Err(Errno::EACCES) if !write && !truncates => None,
                    Err(errno) => return Err(status(errno)),
                };
                if let Some(fh) = fh.filter(|_| truncates) {
                    let changes = SetAttr {
                        size: Some(0),
                        ..SetAttr::default()
                    };
                    match client.setattr(node.id, Some(fh), &changes) {
                        Ok(attr) => node.attr = attr,
                        Err(errno) => {
                            let _ = client.release(node.id, fh, flags);
                            return Err(status(errno));
                        }
                    }
                }
                let action = match disposition {
                    FILE_SUPERSEDE => 0,
                    _ if truncates => 3,
                    _ => 1,
                };
                (node, fh, action)
            }
            None if !creates => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
            None => {
                let (name, parent_path) = components
                    .split_last()
                    .ok_or(STATUS_OBJECT_NAME_COLLISION)?;
                let parent = client
                    .resolve_dir(parent_path)
                    .map_err(|errno| path_status(PathError::Parent(errno)))?;
                if want_dir {
                    let node = client.mkdir(parent, name, NEW_DIR_MODE).map_err(status)?;
                    let fh = client.opendir(node.id).map_err(status)?;
                    (node, Some(fh), 2)
                } else {
                    // A file is created for writing, whatever this open may do with it
                    if flags == libc::O_RDONLY {
                        flags = libc::O_RDWR;
                    }
                    let (node, fh) = client
                        .create(parent, name, NEW_FILE_MODE, flags)
                        .map_err(status)?;
                    (node, Some(fh), 2)
                }
            }
        };
        let is_dir = node.attr.kind == FileType::Directory;
        let id = self.new_id();
        let mut b = Vec::new();
        b.put_u16(89);
        // No oplock, no flags
        b.put_u8(0);
        b.put_u8(0);
        b.put_u32(action);
        put_times(&mut b, &node.attr);
        b.put_u64(allocation(&node.attr));
        b.put_u64(node.attr.size);
        b.put_u32(attributes(&node.attr));
        b.put_u32(0);
        b.put_u64(id);
        b.put_u64(id);
        // No create contexts
        b.put_u32(0);
        b.put_u32(0);
        b.put_u8(0);
        self.opens.insert(
            id,
            Open {
                node: node.id,
                fh,
                flags,
                is_dir,
                writable: !is_dir && flags != libc::O_RDONLY,
                access,
                path,
                delete_on_close,
                listing: None,
                session: h.session_id,
                tree: h.tree_id,
            },
        );
        chain.file_id = Some(id);
        Ok((STATUS_SUCCESS, b))
    }

    fn close(&mut self, id: u64, body: &[u8]) -> Reply {
        // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
        let post_query = u16_at(body, 2).invalid()? & 0x1 != 0;
        let open = self.opens.remove(&id).ok_or(STATUS_FILE_CLOSED)?;
        let attr = post_query
            .then(|| self.client().getattr(open.node, open.file_handle()).ok())
            .flatten();
        self.release(open)?;
        let mut b = Vec::new();
        b.put_u16(60);
        b.put_u16(u16::from(attr.is_some()));
        b.put_u32(0);
        match attr {
            Some(attr) => {
                put_times(&mut b, &attr);
                b.put_u64(allocation(&attr));
                b.put_u64(attr.size);
                b.put_u32(attributes(&attr));
            }
            None => b.resize(b.len() + 52, 0),
        }
        Ok((STATUS_SUCCESS, b))
    }

    /// Closes the opens `which` picks, as when their session or connection ends
    fn close_where(&mut self, which: impl Fn(&Open) -> bool) {
        let ids: Vec<u64> = self
            .opens
            .iter()
            .filter(|(_, open)| which(open))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(open) = self.opens.remove(&id) {
                let _ = self.release(open);
            }
        }
    }

    /// Closes everything: the connection has ended
    pub(crate) fn close_all(&mut self) {
        self.close_where(|_| true);
    }

    /// Releases an open's FUSE handle, then deletes what it names if it was to be
    fn release(&self, open: Open) -> Result<(), u32> {
        let client = self.client();
        if let Some(fh) = open.fh {
            if open.is_dir {
                client.releasedir(open.node, fh).map_err(status)?;
            } else {
                // As close(2) does: FLUSH reports a failure to write back, RELEASE cannot
                let flushed = client.flush(open.node, fh);
                client.release(open.node, fh, open.flags).map_err(status)?;
                flushed.map_err(status)?;
            }
        }
        if open.delete_on_close {
            let path: Vec<&str> = open.path.iter().map(String::as_str).collect();
            let (name, parent_path) = path.split_last().ok_or(STATUS_ACCESS_DENIED)?;
            let parent = client
                .resolve_dir(parent_path)
                .map_err(|errno| path_status(PathError::Parent(errno)))?;
            if open.is_dir {
                client.rmdir(parent, name).map_err(status)?;
                client.forget_path(&path);
            } else {
                client.unlink(parent, name).map_err(status)?;
            }
        }
        Ok(())
    }

    fn read(&self, id: u64, body: &[u8]) -> Reply {
        let length = u32_at(body, 4).invalid()?.min(MAX_IO);
        let offset = u64_at(body, 8).invalid()?;
        let open = self.open(id)?;
        if open.is_dir {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let fh = open.fh.ok_or(STATUS_ACCESS_DENIED)?;
        let data = self
            .client()
            .read(open.node, fh, offset, length, open.flags)
            .map_err(status)?;
        if data.is_empty() && length > 0 {
            return Err(STATUS_END_OF_FILE);
        }
        let mut b = Vec::new();
        b.put_u16(17);
        b.put_u8((HEADER_LEN + 16) as u8);
        b.put_u8(0);
        b.put_u32(data.len() as u32);
        b.put_u32(0);
        b.put_u32(0);
        b.extend_from_slice(&data);
        Ok((STATUS_SUCCESS, b))
    }

    fn write(&self, id: u64, req: &[u8]) -> Reply {
        let body = &req[HEADER_LEN..];
        let data = bytes_at(
            req,
            u16_at(body, 2).invalid()? as usize,
            u32_at(body, 4).invalid()? as usize,
        )
        .invalid()?;
        let offset = u64_at(body, 8).invalid()?;
        let open = self.open(id)?;
        if open.is_dir {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let fh = open
            .fh
            .filter(|_| open.writable)
            .ok_or(STATUS_ACCESS_DENIED)?;
        let written = self
            .client()
            .write(open.node, fh, offset, data, open.flags)
            .map_err(status)?;
        let mut b = Vec::new();
        b.put_u16(17);
        b.put_u16(0);
        b.put_u32(written);
        b.put_u32(0);
        b.put_u32(0);
        b.put_u8(0);
        Ok((STATUS_SUCCESS, b))
    }

    fn query_directory(&mut self, id: u64, req: &[u8]) -> Reply {
        let body = &req[HEADER_LEN..];
        let class = u8_at(body, 2).invalid()?;
        let flags = u8_at(body, 3).invalid()?;
        let pattern = bytes_at(
            req,
            u16_at(body, 24).invalid()? as usize,
            u16_at(body, 26).invalid()? as usize,
        )
        .and_then(from_utf16)
        .invalid()?;
        let room = u32_at(body, 28).invalid()?.min(MAX_IO) as usize;
        if !matches!(class, 1 | 2 | 3 | 12 | 37 | 38) {
            return Err(STATUS_INVALID_INFO_CLASS);
        }
        let open = self.opens.get(&id).ok_or(STATUS_FILE_CLOSED)?;
        if !open.is_dir {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // SMB2_RESTART_SCANS, SMB2_REOPEN
        let first = flags & (0x01 | 0x10) != 0 || open.listing.is_none();
        if first {
            let fh = open.fh.ok_or(STATUS_ACCESS_DENIED)?;
            let pattern = if pattern.is_empty() { "*" } else { &pattern };
            let client = self.client();
            let mut entries = Vec::new();
            // "." and "..", which clients expect first, so that no directory lists as empty
            if convert::matches(pattern, ".") {
                let attr = client.getattr(open.node, None).map_err(status)?;
                entries.push((".".to_owned(), attr));
            }
            if convert::matches(pattern, "..") {
                let parent: Vec<&str> = open.path.iter().map(String::as_str).collect();
                let parent = parent.split_last().map_or(&[][..], |(_, parent)| parent);
                let attr = client.resolve(parent).map_err(path_status)?.attr;
                entries.push(("..".to_owned(), attr));
            }
            entries.extend(list(client, open.node, fh, pattern)?);
            if entries.is_empty() {
                return Err(STATUS_NO_SUCH_FILE);
            }
            if let Some(open) = self.opens.get_mut(&id) {
                open.listing = Some((entries, 0));
            }
        }
        let open = self.opens.get_mut(&id).ok_or(STATUS_FILE_CLOSED)?;
        let (entries, next) = open.listing.as_mut().ok_or(STATUS_FILE_CLOSED)?;
        let mut buf: Vec<u8> = Vec::new();
        let mut last = None;
        while let Some((name, attr)) = entries.get(*next) {
            let record = entry(class, name, attr).ok_or(STATUS_INVALID_INFO_CLASS)?;
            let start = buf.len().next_multiple_of(8);
            if start + record.len() > room {
                break;
            }
            if let Some(last) = last {
                buf.set_u32(last, (start - last) as u32);
            }
            buf.resize(start, 0);
            buf.extend_from_slice(&record);
            last = Some(start);
            *next += 1;
            // SMB2_RETURN_SINGLE_ENTRY
            if flags & 0x02 != 0 {
                break;
            }
        }
        if last.is_none() {
            return Err(if *next >= entries.len() {
                STATUS_NO_MORE_FILES
            } else {
                STATUS_INFO_LENGTH_MISMATCH
            });
        }
        let mut b = Vec::new();
        b.put_u16(9);
        b.put_u16((HEADER_LEN + 8) as u16);
        b.put_u32(buf.len() as u32);
        b.extend_from_slice(&buf);
        Ok((STATUS_SUCCESS, b))
    }

    fn query_info(&self, id: u64, body: &[u8]) -> Reply {
        let info_type = u8_at(body, 2).invalid()?;
        let class = u8_at(body, 3).invalid()?;
        let room = u32_at(body, 4).invalid()? as usize;
        let open = self.open(id)?;
        let client = self.client();
        let mut d = Vec::new();
        match (info_type, class) {
            // SMB2_0_INFO_FILE
            (1, _) => {
                let attr = client
                    .getattr(open.node, open.file_handle())
                    .map_err(status)?;
                let name = utf16(&format!("\\{}", open.path.join("\\")));
                match class {
                    4 => put_basic(&mut d, &attr),
                    5 => put_standard(&mut d, &attr, open.delete_on_close),
                    6 => d.put_u64(attr.ino.0),
                    // EaSize, mode and alignment
                    7 | 16 | 17 => d.put_u32(0),
                    8 => d.put_u32(open.access),
                    9 => {
                        d.put_u32(name.len() as u32);
                        d.extend_from_slice(&name);
                    }
                    // Position
                    14 => d.put_u64(0),
                    // The 8.3 name: there are none
                    21 => return Err(STATUS_NOT_SUPPORTED),
                    18 => {
                        put_basic(&mut d, &attr);
                        put_standard(&mut d, &attr, open.delete_on_close);
                        d.put_u64(attr.ino.0);
                        // Ea, access, position, mode, alignment
                        d.put_u32(0);
                        d.put_u32(open.access);
                        d.put_u64(0);
                        d.put_u32(0);
                        d.put_u32(0);
                        d.put_u32(name.len() as u32);
                        d.extend_from_slice(&name);
                    }
                    // Streams: a file's one, unnamed; a directory has none
                    22 if !open.is_dir => {
                        let stream = utf16("::$DATA");
                        d.put_u32(0);
                        d.put_u32(stream.len() as u32);
                        d.put_u64(attr.size);
                        d.put_u64(allocation(&attr));
                        d.extend_from_slice(&stream);
                    }
                    22 => {}
                    34 => {
                        put_times(&mut d, &attr);
                        d.put_u64(allocation(&attr));
                        d.put_u64(attr.size);
                        d.put_u32(attributes(&attr));
                        d.put_u32(0);
                    }
                    35 => {
                        d.put_u32(attributes(&attr));
                        d.put_u32(0);
                    }
                    _ => return Err(STATUS_INVALID_INFO_CLASS),
                }
            }
            // SMB2_0_INFO_FILESYSTEM
            (2, _) => {
                let stat = client.statfs(INodeNo::ROOT).map_err(status)?;
                let unit = if stat.frsize > 0 {
                    stat.frsize
                } else {
                    stat.bsize
                }
                .max(1);
                match class {
                    1 => {
                        let label = utf16(&self.share.name);
                        d.put_u64(0);
                        d.put_u32(0);
                        d.put_u32(label.len() as u32);
                        d.put_u16(0);
                        d.extend_from_slice(&label);
                    }
                    3 => {
                        d.put_u64(stat.blocks);
                        d.put_u64(stat.bavail);
                        d.put_u32(1);
                        d.put_u32(unit);
                    }
                    // FILE_DEVICE_DISK
                    4 => {
                        d.put_u32(7);
                        d.put_u32(0);
                    }
                    5 => {
                        // Case-sensitive search, case-preserved and Unicode names; no streams
                        // or ACLs, which keeps clients from asking for them
                        let mut flags = 0x1 | 0x2 | 0x4;
                        if self.share.read_only {
                            flags |= 0x8_0000;
                        }
                        let name = utf16("NTFS");
                        d.put_u32(flags);
                        d.put_u32(if stat.namelen > 0 { stat.namelen } else { 255 });
                        d.put_u32(name.len() as u32);
                        d.extend_from_slice(&name);
                    }
                    7 => {
                        d.put_u64(stat.blocks);
                        d.put_u64(stat.bavail);
                        d.put_u64(stat.bfree);
                        d.put_u32(1);
                        d.put_u32(unit);
                    }
                    11 => {
                        for value in [unit, unit, unit, unit, 0, 0, 0] {
                            d.put_u32(value);
                        }
                    }
                    _ => return Err(STATUS_INVALID_INFO_CLASS),
                }
            }
            // Security descriptors and quotas
            _ => return Err(STATUS_NOT_SUPPORTED),
        }
        let status = if d.len() > room {
            d.truncate(room);
            STATUS_BUFFER_OVERFLOW
        } else {
            STATUS_SUCCESS
        };
        let mut b = Vec::new();
        b.put_u16(9);
        b.put_u16((HEADER_LEN + 8) as u16);
        b.put_u32(d.len() as u32);
        b.extend_from_slice(&d);
        Ok((status, b))
    }

    fn set_info(&mut self, id: u64, req: &[u8]) -> Reply {
        let body = &req[HEADER_LEN..];
        let info_type = u8_at(body, 2).invalid()?;
        let class = u8_at(body, 3).invalid()?;
        let d = bytes_at(
            req,
            u16_at(body, 8).invalid()? as usize,
            u32_at(body, 4).invalid()? as usize,
        )
        .invalid()?;
        if info_type != 1 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        if self.share.read_only {
            return Err(STATUS_ACCESS_DENIED);
        }
        let open = self.open(id)?;
        let client = self.client();
        match class {
            // Basic: times, of which 0 and -1 change nothing, and attributes
            4 => {
                let time = |at: usize| -> Result<Option<SystemTime>, u32> {
                    let value = u64_at(d, at).invalid()?;
                    Ok((value != 0 && value != u64::MAX).then(|| convert::system_time(value)))
                };
                let changes = SetAttr {
                    crtime: time(0)?,
                    atime: time(8)?,
                    mtime: time(16)?,
                    ..SetAttr::default()
                };
                if changes.crtime.is_some() || changes.atime.is_some() || changes.mtime.is_some() {
                    client
                        .setattr(open.node, open.file_handle(), &changes)
                        .map_err(status)?;
                }
                let attributes = u32_at(d, 32).invalid()?;
                if attributes != 0 && !open.is_dir {
                    // Only FILE_ATTRIBUTE_READONLY is kept, as the absence of write bits
                    let attr = client
                        .getattr(open.node, open.file_handle())
                        .map_err(status)?;
                    let perm = u32::from(attr.perm);
                    let mode = if attributes & FILE_ATTRIBUTE_READONLY != 0 {
                        perm & !0o222
                    } else if perm & 0o222 == 0 {
                        perm | 0o200
                    } else {
                        perm
                    };
                    if mode != perm {
                        let changes = SetAttr {
                            mode: Some(mode),
                            ..SetAttr::default()
                        };
                        client
                            .setattr(open.node, open.file_handle(), &changes)
                            .map_err(status)?;
                    }
                }
            }
            // Rename
            10 => {
                let replace = u8_at(d, 0).invalid()? != 0;
                let len = u32_at(d, 16).invalid()? as usize;
                let target = bytes_at(d, 20, len)
                    .and_then(from_utf16)
                    .ok_or(STATUS_OBJECT_NAME_INVALID)?;
                let target = parse_path(&target)?;
                self.rename(id, target, replace)?;
            }
            // Disposition, and its extended form
            13 | 64 => {
                let delete = if class == 13 {
                    u8_at(d, 0).invalid()? != 0
                } else {
                    u32_at(d, 0).invalid()? & 0x1 != 0
                };
                if delete && open.is_dir && !is_empty_dir(client, open)? {
                    return Err(STATUS_DIRECTORY_NOT_EMPTY);
                }
                if let Some(open) = self.opens.get_mut(&id) {
                    open.delete_on_close = delete;
                }
            }
            // End of file
            20 => {
                let changes = SetAttr {
                    size: Some(u64_at(d, 0).invalid()?),
                    ..SetAttr::default()
                };
                client
                    .setattr(open.node, open.file_handle(), &changes)
                    .map_err(status)?;
            }
            // Allocation, position and mode: nothing to keep
            14 | 16 | 19 => {}
            _ => return Err(STATUS_NOT_SUPPORTED),
        }
        Ok((STATUS_SUCCESS, vec![2, 0]))
    }

    fn rename(&mut self, id: u64, target: Vec<String>, replace: bool) -> Result<(), u32> {
        let open = self.open(id)?;
        let client = self.client();
        let from: Vec<&str> = open.path.iter().map(String::as_str).collect();
        let to: Vec<&str> = target.iter().map(String::as_str).collect();
        let (Some((name, from_parent)), Some((newname, to_parent))) =
            (from.split_last(), to.split_last())
        else {
            return Err(STATUS_ACCESS_DENIED);
        };
        match client.resolve(&to) {
            Ok(existing) if existing.id == open.node => {}
            Ok(_) if !replace => return Err(STATUS_OBJECT_NAME_COLLISION),
            // An existing directory is never replaced (MS-FSA 2.1.5.15.12)
            Ok(Node { attr, .. }) if attr.kind == FileType::Directory => {
                return Err(STATUS_ACCESS_DENIED);
            }
            Ok(_) | Err(PathError::Last(Errno::ENOENT)) => {}
            Err(err) => return Err(path_status(err)),
        }
        let parent = client
            .resolve_dir(from_parent)
            .map_err(|errno| path_status(PathError::Parent(errno)))?;
        let newparent = client
            .resolve_dir(to_parent)
            .map_err(|errno| path_status(PathError::Parent(errno)))?;
        client
            .rename(parent, name, newparent, newname)
            .map_err(status)?;
        client.forget_path(&from);
        client.forget_path(&to);
        if let Some(open) = self.opens.get_mut(&id) {
            open.path = target;
        }
        Ok(())
    }
}

/// The components of a path from the share's root. Named streams are not served
fn parse_path(name: &str) -> Result<Vec<String>, u32> {
    let name = name.strip_suffix("::$DATA").unwrap_or(name);
    if name.contains(':') {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let components: Vec<String> = name
        .split('\\')
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect();
    if components
        .iter()
        .any(|c| c == "." || c == ".." || c.contains('/'))
    {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(components)
}

/// The directory's entries that match `pattern`, with their attributes
fn list(
    client: &Client,
    node: INodeNo,
    fh: u64,
    pattern: &str,
) -> Result<Vec<(String, FileAttr)>, u32> {
    let mut entries = Vec::new();
    let mut offset = 0;
    loop {
        let batch = client
            .readdir(node, fh, offset, READDIR_SIZE)
            .map_err(status)?;
        let Some(last) = batch.last() else {
            break;
        };
        offset = last.offset;
        for entry in batch {
            // SMB names are Unicode
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            if name == "." || name == ".." || !convert::matches(pattern, name) {
                continue;
            }
            // A listing carries attributes, which READDIR does not give
            match client.lookup(node, name) {
                Ok(found) => entries.push((name.to_owned(), found.attr)),
                // Gone since READDIR listed it
                Err(Errno::ENOENT) => {}
                Err(errno) => return Err(status(errno)),
            }
        }
    }
    Ok(entries)
}

fn is_empty_dir(client: &Client, open: &Open) -> Result<bool, u32> {
    let fh = open.fh.ok_or(STATUS_ACCESS_DENIED)?;
    let batch = client
        .readdir(open.node, fh, 0, READDIR_SIZE)
        .map_err(status)?;
    Ok(batch
        .iter()
        .all(|entry| entry.name == "." || entry.name == ".."))
}

/// One entry of a directory listing in `class`, or None for a class not served. Its
/// NextEntryOffset is left 0
fn entry(class: u8, name: &str, attr: &FileAttr) -> Option<Vec<u8>> {
    let name = utf16(name);
    let mut e = Vec::new();
    // NextEntryOffset, FileIndex
    e.put_u32(0);
    e.put_u32(0);
    if class == 12 {
        e.put_u32(name.len() as u32);
        e.extend_from_slice(&name);
        return Some(e);
    }
    put_times(&mut e, attr);
    e.put_u64(attr.size);
    e.put_u64(allocation(attr));
    e.put_u32(attributes(attr));
    e.put_u32(name.len() as u32);
    match class {
        // FileDirectoryInformation
        1 => {}
        // FileFullDirectoryInformation: EaSize
        2 => e.put_u32(0),
        // FileIdFullDirectoryInformation: EaSize, Reserved, FileId
        38 => {
            e.put_u32(0);
            e.put_u32(0);
            e.put_u64(attr.ino.0);
        }
        // FileBothDirectoryInformation and FileIdBothDirectoryInformation: EaSize, no short
        // name, and for the latter Reserved and FileId
        3 | 37 => {
            e.put_u32(0);
            e.resize(e.len() + 2 + 24, 0);
            if class == 37 {
                e.put_u16(0);
                e.put_u64(attr.ino.0);
            }
        }
        _ => return None,
    }
    e.extend_from_slice(&name);
    Some(e)
}

fn attributes(attr: &FileAttr) -> u32 {
    if attr.kind == FileType::Directory {
        // A directory's write bits govern its entries, not a DOS read-only flag
        FILE_ATTRIBUTE_DIRECTORY
    } else if attr.perm & 0o222 == 0 {
        FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    }
}

fn allocation(attr: &FileAttr) -> u64 {
    attr.blocks.saturating_mul(512)
}

/// Creation, last access, last write and change times
fn put_times(out: &mut Vec<u8>, attr: &FileAttr) {
    for time in [attr.crtime, attr.atime, attr.mtime, attr.ctime] {
        out.put_u64(convert::filetime(time));
    }
}

fn put_basic(out: &mut Vec<u8>, attr: &FileAttr) {
    put_times(out, attr);
    out.put_u32(attributes(attr));
    out.put_u32(0);
}

fn put_standard(out: &mut Vec<u8>, attr: &FileAttr, delete_pending: bool) {
    out.put_u64(allocation(attr));
    out.put_u64(attr.size);
    out.put_u32(attr.nlink);
    out.put_u8(u8::from(delete_pending));
    out.put_u8(u8::from(attr.kind == FileType::Directory));
    out.put_u16(0);
}

fn path_status(err: PathError) -> u32 {
    match err {
        PathError::Parent(Errno::ENOENT | Errno::ENOTDIR) => STATUS_OBJECT_PATH_NOT_FOUND,
        PathError::Parent(errno) | PathError::Last(errno) => status(errno),
    }
}

/// The NTSTATUS for an errno the filesystem replied with
fn status(errno: Errno) -> u32 {
    match convert::error_kind(errno) {
        ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        ErrorKind::NotADirectory => STATUS_NOT_A_DIRECTORY,
        ErrorKind::IsDirectory => STATUS_FILE_IS_A_DIRECTORY,
        ErrorKind::AccessDenied => STATUS_ACCESS_DENIED,
        ErrorKind::Exists => STATUS_OBJECT_NAME_COLLISION,
        ErrorKind::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        ErrorKind::NotSupported => STATUS_NOT_SUPPORTED,
        ErrorKind::NameInvalid => STATUS_OBJECT_NAME_INVALID,
        ErrorKind::NotSameDevice => STATUS_NOT_SAME_DEVICE,
        ErrorKind::DiskFull => STATUS_DISK_FULL,
        ErrorKind::QuotaExceeded => STATUS_QUOTA_EXCEEDED,
        ErrorKind::InvalidParameter => STATUS_INVALID_PARAMETER,
        ErrorKind::Sharing => STATUS_SHARING_VIOLATION,
        ErrorKind::Other => STATUS_UNEXPECTED_IO_ERROR,
    }
}
