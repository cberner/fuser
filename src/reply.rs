//! Filesystem operation reply
//!
//! A reply handler object is created to guarantee that each fuse request receives a reponse exactly once.
//! Either the request logic will call the one of the reply handler's self-destructive methods, 
//! or, if the reply handler goes out of scope before that happens, the drop trait will send an error response. 

use crate::{Container, Bytes, KernelConfig};
use crate::ll::{self, reply::DirentBuf};
#[cfg(feature = "abi-7-21")]
use crate::ll::reply::{DirentPlusBuf};
#[cfg(feature = "abi-7-40")]
use crate::{consts::FOPEN_PASSTHROUGH, passthrough::BackingId};
#[allow(unused_imports)]
use log::{error, warn, info, debug};
use std::fmt;
use std::io::IoSlice;
#[cfg(feature = "abi-7-40")]
use std::os::fd::BorrowedFd;
use std::time::{Duration, SystemTime};
use zerocopy::IntoBytes;
#[cfg(feature = "serializable")]
use serde::{Deserialize, Serialize};

/// Generic reply callback to send data
pub(crate) trait ReplySender: Send + Sync + Unpin + 'static {
    /// Send data.
    fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()>;
    /// Open a backing file
    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId>;
}

impl fmt::Debug for Box<dyn ReplySender> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Box<ReplySender>")
    }
}

/// ReplyHander is a struct which holds the unique identifiers needed to reply
/// to a specific request. Traits are implemented on the struct so that ownership
/// of the struct determines whether the identifiers have ever been used. 
/// This guarantees that a reply is send at most once per request.
#[derive(Debug)]
pub(crate) struct ReplyHandler {
    /// Unique id of the request to reply to
    unique: ll::RequestId,
    /// Closure to call for sending the reply
    sender: Option<Box<dyn ReplySender>>,
}

impl ReplyHandler {
    /// Create a reply handler for a specific request identifier
    pub(crate) fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyHandler {
        let sender = Box::new(sender);
        ReplyHandler {
            unique: ll::RequestId(unique),
            sender: Some(sender),
        }
    }

    /// Reply to a request with a formatted reponse. Can be called
    /// more than once (the `&mut self`` argument does not consume `self`)
    /// Avoid using this variant unless you know what you are doing!
    fn send_ll_mut(&mut self, response: &ll::Response<'_>) {
        assert!(self.sender.is_some());
        let sender = self.sender.take().unwrap();
        let res = response.with_iovec(self.unique, |iov| sender.send(iov));
        if let Err(err) = res {
            error!("Failed to send FUSE reply: {}", err);
        }
    }
    /// Reply to a request with a formatted reponse. May be called
    /// only once (the `mut self`` argument consumes `self`).
    /// Use this variant for general replies. 
    fn send_ll(mut self, response: &ll::Response<'_>) {
        self.send_ll_mut(response)
    }

}

/// Drop is implemented on ReplyHandler so that if the program logic fails 
/// (for example, due to an interrupt or a panic),
/// a reply will be sent when the Reply Handler falls out of scope.
impl Drop for ReplyHandler {
    fn drop(&mut self) {
        if self.sender.is_some() {
            warn!(
                "Reply not sent for operation {}, replying with I/O error",
                self.unique.0
            );
            self.send_ll_mut(&ll::Response::new_error(ll::Errno::EIO));
        }
    }
}

/// File types
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serializable", derive(Serialize, Deserialize))]
pub enum FileType {
    /// Named pipe (S_IFIFO)
    NamedPipe,
    /// Character device (S_IFCHR)
    CharDevice,
    /// Block device (S_IFBLK)
    BlockDevice,
    /// Directory (S_IFDIR)
    Directory,
    /// Regular file (S_IFREG)
    RegularFile,
    /// Symbolic link (S_IFLNK)
    Symlink,
    /// Unix domain socket (S_IFSOCK)
    Socket,
}

/// File attributes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serializable", derive(Serialize, Deserialize))]
pub struct FileAttr {
    /// Unique number for this file
    pub ino: u64,
    /// Size in bytes
    pub size: u64,
    /// Size in blocks
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
    /// Block size
    pub blksize: u32,
    /// Flags (macOS only, see chflags(2))
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serializable", derive(Serialize, Deserialize))]
/// An entry in the kernel's file cache
pub struct Entry {
    /// file inode number
    pub ino: u64,
    /// file generation number
    pub generation: Option<u64>,
    /// duration to cache file identity
    pub file_ttl: Duration,
    /// file attributes
    pub attr: FileAttr,
    /// duration to cache file attributes
    pub attr_ttl: Duration,
}

#[derive(Debug, Clone)] //TODO #[derive(Copy)]
#[cfg_attr(feature = "serializable", derive(Serialize, Deserialize))]
/// Open file handle response data
pub struct Open {
    /// File handle for the opened file
    pub fh: u64,
    /// Flags for the opened file
    pub flags: u32
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serializable", derive(Serialize, Deserialize))]
/// A sinegle directory entry.
/// The `'name` lifetime parameter is associated with the `name` field if it is from borrowed Bytes.
pub struct Dirent<'name> {
    /// file inode number
    pub ino: u64,
    /// entry number in directory
    pub offset: i64,
    /// kind of file
    pub kind: FileType,
    /// name of file
    pub name: Bytes<'name>,
}

/// A list of directory entries.
pub type DirentList<'dir, 'name> = Container<'dir, Dirent<'name>>;

/// A list of directory entries, plus additional file data for the kernel cache.
pub type DirentPlusList<'dir, 'name> = Container<'dir, (Dirent<'name>, Entry)>;


#[cfg(target_os = "macos")]
#[derive(Debug)]
/// Xtimes response data
pub struct XTimes {
    /// Backup time
    pub bkuptime: SystemTime,
    /// Creation time
    pub crtime: SystemTime
}

#[derive(Copy, Clone, Debug)]
/// Statfs response data
pub struct Statfs {
    /// Total blocks (in units of frsize)
    pub blocks: u64,
    /// Free blocks
    pub bfree: u64,
    /// Free blocks for unprivileged users
    pub bavail: u64,
    /// Total inodes
    pub files: u64,
    /// Free inodes
    pub ffree: u64,
    /// Filesystem block size
    pub bsize: u32,
    /// Maximum filename length
    pub namelen: u32,
    /// Fundamental file system block size
    pub frsize: u32
}

#[derive(Copy, Clone, Debug)]
/// File lock response data
pub struct Lock {
    /// start of locked byte range
    pub start: u64,
    /// end of locked byte range
    pub end: u64,
    // NOTE: lock field is defined as u32 in fuse_kernel.h in libfuse. However, it is treated as signed
    // TODO enum {F_RDLCK, F_WRLCK, F_UNLCK}
    /// kind of lock (read and/or write)
    pub typ: i32,
    /// PID of process blocking our lock
    pub pid: u32,
}

/// `Xattr` represents the response for extended attribute operations (`getxattr`, `listxattr`).
/// It can either indicate the size of the attribute data or provide the data itself
/// using `Bytes` for flexible ownership.
#[derive(Debug)]
pub enum Xattr<'a> {
    /// Indicates the size of the extended attribute data. Used when the caller
    /// provides a zero-sized buffer to query the required buffer size.
    Size(u32),
    /// Contains the extended attribute data. `Bytes` allows this data to be
    /// returned in a zero-copy data ownership model.
    Data(Bytes<'a>),
}

#[cfg(feature = "abi-7-11")]
#[derive(Debug)]
/// File io control reponse data
pub struct Ioctl<'a> {
    /// Result of the ioctl operation
    pub result: i32,
    /// Data to be returned with the ioctl operation
    pub data: Bytes<'a>
}

//
// Methods to reply to a request for each kind of data
//

impl ReplyHandler {

    /// Reply to a general request with Ok
    pub fn ok(self) {
        self.send_ll(&ll::Response::new_empty());
    }

    /// Reply to a general request with an error code
    pub fn error(self, err: ll::Errno) {
        self.send_ll(&ll::Response::new_error(err));
    }

    /// Reply to a general request with data
    pub fn data<'a>(self, data: Bytes<'a>) {
        self.send_ll(&ll::Response::new_slice(&data.borrow()));
    }

    // Reply to an init request with available features
    pub fn config(self, capabilities: u64, config: KernelConfig) {
        let flags = capabilities & config.requested; // use features requested by fs and reported as capable by kernel

        let init = ll::fuse_abi::fuse_init_out {
            major: ll::fuse_abi::FUSE_KERNEL_VERSION,
            minor: ll::fuse_abi::FUSE_KERNEL_MINOR_VERSION,
            max_readahead: config.max_readahead,
            #[cfg(not(feature = "abi-7-36"))]
            flags: flags as u32,
            #[cfg(feature = "abi-7-36")]
            flags: (flags | ll::fuse_abi::consts::FUSE_INIT_EXT) as u32,
            #[cfg(not(feature = "abi-7-13"))]
            unused: 0,
            #[cfg(feature = "abi-7-13")]
            max_background: config.max_background,
            #[cfg(feature = "abi-7-13")]
            congestion_threshold: config.congestion_threshold(),
            max_write: config.max_write,
            #[cfg(feature = "abi-7-23")]
            time_gran: config.time_gran.as_nanos() as u32,
            #[cfg(all(feature = "abi-7-23", not(feature = "abi-7-28")))]
            reserved: [0; 9],
            #[cfg(feature = "abi-7-28")]
            max_pages: config.max_pages(),
            #[cfg(feature = "abi-7-28")]
            unused2: 0,
            #[cfg(all(feature = "abi-7-28", not(feature = "abi-7-36")))]
            reserved: [0; 8],
            #[cfg(feature = "abi-7-36")]
            flags2: (flags >> 32) as u32,
            #[cfg(all(feature = "abi-7-36", not(feature = "abi-7-40")))]
            reserved: [0; 7],
            #[cfg(feature = "abi-7-40")]
            max_stack_depth: config.max_stack_depth,
            #[cfg(feature = "abi-7-40")]
            reserved: [0; 6],
        };
        self.send_ll(&ll::Response::new_data(init.as_bytes()));
    }

    /// Reply to a request with a file entry
    pub fn entry(self, entry: Entry) {
        self.send_ll(&ll::Response::new_entry(
            ll::INodeNo(entry.ino),
            ll::Generation(entry.generation.unwrap_or(1)),
            entry.file_ttl,
            &entry.attr.into(),
            entry.attr_ttl,

        ));
    }

    /// Reply to a request with a file attributes
    pub fn attr(self, attr: FileAttr, ttl: Duration) {
        self.send_ll(&ll::Response::new_attr(&ttl, &attr.into()));
    }

    #[cfg(target_os = "macos")]
    /// Reply to a request with xtimes attributes
    pub fn xtimes(self, xtimes: XTimes) {
        self.send_ll(&ll::Response::new_xtimes(xtimes.bkuptime, xtimes.crtime))
    }

    /// Reply to a request with a newly opened file handle
    pub fn opened(self, open: Open) {
        #[cfg(feature = "abi-7-40")]
        assert_eq!(open.flags & FOPEN_PASSTHROUGH, 0);
        self.send_ll(&ll::Response::new_open(ll::FileHandle(open.fh), open.flags, 0))
    }

    /// Reply to a request with the number of bytes written
    pub fn written(self, size: u32) {
        self.send_ll(&ll::Response::new_write(size))
    }

    /// Reply to a statfs request 
    pub fn statfs(
        self,
        statfs: Statfs
    ) {
        self.send_ll(&ll::Response::new_statfs(
            statfs.blocks, statfs.bfree, statfs.bavail, statfs.files, statfs.ffree, statfs.bsize, statfs.namelen, statfs.frsize,
        ))
    }

    /// Reply to a request with a newle created file entry and its newly open file handle
    pub fn created(self, entry: Entry, open: Open) {
        #[cfg(feature = "abi-7-40")]
        assert_eq!(open.flags & FOPEN_PASSTHROUGH, 0);
        self.send_ll(&ll::Response::new_create(
            &entry.file_ttl,
            &entry.attr.into(),
            ll::Generation(entry.generation.unwrap_or(1)),
            ll::FileHandle(open.fh),
            open.flags,
            0,
        ))
    }

    /// Reply to a request with a file lock
    pub fn locked(self, lock: Lock) {
        self.send_ll(&ll::Response::new_lock(&ll::Lock{
            range: (lock.start, lock.end),
            typ: lock.typ,
            pid: lock.pid,
        }))
    }

    /// Reply to a request with a bmap
    pub fn bmap(self, block: u64) {
        self.send_ll(&ll::Response::new_bmap(block))
    }

    #[cfg(feature = "abi-7-11")]
    /// Reply to a request with an ioctl
    pub fn ioctl(self, ioctl: Ioctl<'_>) {
        self.send_ll(&ll::Response::new_ioctl(ioctl.result, &ioctl.data.borrow()));
    }

    #[cfg(feature = "abi-7-11")]
    /// Reply to a request with a poll result
    pub fn poll(self, revents: u32) {
        self.send_ll(&ll::Response::new_poll(revents))
    }

    /// Reply to a request with a filled directory buffer
    pub fn dir(
        self,
        entries_list: &DirentList<'_, '_>,
        size: usize,
        min_offset: i64,
    ) {
        let mut buf = DirentBuf::new(size);
        let entries = match entries_list.try_borrow(){
            Ok(entries) => entries,
            Err(e) => {
                log::error!("ReplyHandler::dir: Borrow Error: {:?}", e);
                return;
            }
        };
        for item in entries.iter() {
            if item.offset < min_offset {
                log::debug!("ReplyHandler::dir: skipping item with offset #{}", item.offset);
                continue;
            } else {
                log::debug!("ReplyHandler::dir: processing item with offset #{}", item.offset);
            }
            let full= buf.push(item);
            if full {
                log::debug!("ReplyHandler::dir: buffer full!");
                break;
            }
        }
        self.send_ll(&buf.into());
    }

    #[cfg(feature = "abi-7-21")]
    // Reply to a request with a filled directory plus buffer
    pub fn dirplus(
        self,
        entries_plus_list: &DirentPlusList<'_, '_>,
        size: usize,
        min_offset: i64,
    ) {
        let mut buf = DirentPlusBuf::new(size);
        let entries = match entries_plus_list.try_borrow(){
            Ok(entries) => entries,
            Err(e) => {
                log::error!("ReplyHandler::dirplus: Borrow Error: {:?}", e);
                return;
            }
        };
        for (dirent, entry) in entries.iter() {
            if dirent.offset < min_offset {
                log::debug!("ReplyHandler::dirplus: skipping item with offset #{}", dirent.offset);
                continue;
            } else {
                log::debug!("ReplyHandler::dirplus: processing item with offset #{}", dirent.offset);
            }
            let full = buf.push(&dirent, &entry);
            if full {
                log::debug!("ReplyHandler::dirplus: buffer full!");
                break;
            }
        }
        self.send_ll(&buf.into());
    }

    /// Reply to a request with extended attributes.
    pub fn xattr(self, reply: Xattr<'_>) {
        match reply {
            Xattr::Size(s) => self.xattr_size(s),
            Xattr::Data(d) => self.xattr_data(d),
        }
    }

    /// Reply to a request with the size of an xattr result.
    pub fn xattr_size(self, size: u32) {
        self.send_ll(&ll::Response::new_xattr_size(size))
    }

    /// Reply to a request with the data in an xattr result.
    pub fn xattr_data(self, data: Bytes<'_>) {
        self.send_ll(&ll::Response::new_slice(&data.borrow()))
    }

    #[cfg(feature = "abi-7-24")]
    /// Reply to a request with a seeked offset
    pub fn offset(self, offset: i64) {
        self.send_ll(&ll::Response::new_lseek(offset))
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{FileAttr, FileType};
    use std::io::IoSlice;
    use std::sync::mpsc::{sync_channel, SyncSender};
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};
    use zerocopy::{Immutable, IntoBytes};
    use std::ffi::OsString;

    #[derive(Debug, IntoBytes, Immutable)]
    #[repr(C)]
    struct Data {
        a: u8,
        b: u8,
        c: u16,
    }

    #[test]
    fn serialize_empty() {
        assert!(().as_bytes().is_empty());
    }

    #[test]
    fn serialize_slice() {
        let data: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(data.as_bytes(), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn serialize_struct() {
        let data = Data {
            a: 0x12,
            b: 0x34,
            c: 0x5678,
        };
        assert_eq!(data.as_bytes(), [0x12, 0x34, 0x78, 0x56]);
    }

    struct AssertSender {
        expected: Vec<u8>,
    }

    impl super::ReplySender for AssertSender {
        fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()> {
            let mut v = vec![];
            for x in data {
                v.extend_from_slice(x)
            }
            assert_eq!(self.expected, v);
            Ok(())
        }

        #[cfg(feature = "abi-7-40")]
        fn open_backing(&self, _fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
            unreachable!()
        }
    }

    #[test]
    fn reply_raw() {
        let data = Data {
            a: 0x12,
            b: 0x34,
            c: 0x5678,
        };
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x12, 0x34, 0x78, 0x56,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.send_ll(&ll::Response::new_data(data.as_bytes()));
    }

    #[test]
    fn reply_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xbe, 0xff, 0xff, 0xff, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        use crate::ll::Errno;
        replyhandler.error(Errno::from_i32(66));
    }

    #[test]
    fn reply_empty() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.ok();
    }

    #[test]
    fn reply_data() {
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.data(Bytes::Ref(&[0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn reply_entry() {
        // prepare the expected message
        let mut expected = Vec::new();
        expected.extend_from_slice(&[
                // header
                0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
                // ino
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // generation
                0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // ttl
                0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                // file attributes
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // file times (s)
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        #[cfg(target_os = "macos")]
        expected.extend_from_slice(&[
                // crtime (s)
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        expected.extend_from_slice(&[
                // file times (ns)
                0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00,
        ]);
        #[cfg(target_os = "macos")]
        expected.extend_from_slice([
                // crtime (ns)
                0x78, 0x56, 0x00, 0x00,
        ]);
        expected.extend_from_slice(&[
                // file permissions
                0xa4, 0x81, 0x00, 0x00,
                // file owners
                0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
                0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
        ]);
        #[cfg(target_os = "macos")]
        expected.extend_from_slice(&[
                // flags
                0x99, 0x00, 0x00, 0x00,
        ]);
        #[cfg(feature = "abi-7-9")]
        expected.extend_from_slice(&[
                // blksize
                0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
        // correct the header
        expected[0] = (expected.len()) as u8;
        // test reply will be compare with the expected message
        let sender = AssertSender { expected };
        // prepare the test reply
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = FileAttr {
            ino: 0x11,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xbb,
        };
        // send the test reply
        replyhandler.entry(
            Entry{
                ino: attr.ino,
                generation: Some(0xaa),
                file_ttl: ttl,
                attr: attr,
                attr_ttl: ttl,
            }
        );
    }

    #[test]
    fn reply_attr() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00,
                0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00,
                0x00, 0x00,
            ]
        } else {
            vec![
                0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00,
                0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
            ]
        };

        if cfg!(feature = "abi-7-9") {
            expected.extend_from_slice(&[0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }
        expected[0] = expected.len() as u8;

        let sender = AssertSender { expected };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = FileAttr {
            ino: 0x11,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xbb,
        };
        replyhandler.attr(attr, ttl);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn reply_xtimes() {
        let sender = AssertSender {
            expected: vec![
                0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        replyhandler.xtimes(
            XTimes{
                bkuptime: time,
                crtime: time,
            }
        );
    }

    #[test]
    fn reply_open() {
        let sender = AssertSender {
            expected: vec![
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.opened(
            Open { fh: 0x1122, flags: 0x33}
        );
    }

    #[test]
    fn reply_write() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.written(0x1122);
    }

    #[test]
    fn reply_statfs() {
        let sender = AssertSender {
            expected: vec![
                0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x66, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.statfs(
            Statfs{
                blocks: 0x11,
                bfree: 0x22,
                bavail: 0x33,
                files: 0x44,
                ffree: 0x55,
                bsize: 0x66,
                namelen: 0x77,
                frsize: 0x88
            }
        );
    }

    #[test]
    fn reply_create() {
        let mut expected = if cfg!(target_os = "macos") {
            vec![
                0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56,
                0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
                0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0xbb, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        } else {
            vec![
                0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
                0x78, 0x56, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00,
                0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        };

        if cfg!(feature = "abi-7-9") {
            let insert_at = expected.len() - 16;
            expected.splice(
                insert_at..insert_at,
                vec![0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            );
        }
        expected[0] = (expected.len()) as u8;

        let sender = AssertSender { expected };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = FileAttr {
            ino: 0x11,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xdd,
        };
        replyhandler.created(
            Entry {
                ino: attr.ino,
                generation: Some(0xaa),
                file_ttl: ttl,
                attr: attr,
                attr_ttl: ttl,
            },
            Open {
                fh: 0xbb,
                flags: 0x0f
            }
        );
    }

    #[test]
    fn reply_lock() {
        let sender = AssertSender {
            expected: vec![
                0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.locked(
            Lock {
                start: 0x11,
                end: 0x22,
                typ: 0x33,
                pid: 0x44
            }
        );
    }

    #[test]
    fn reply_bmap() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.bmap(0x1234);
    }

    #[test]
    fn reply_directory() {
        let sender = AssertSender {
            expected: vec![
                0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0xbb, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x68, 0x65,
                0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00, 0xdd, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00,
                0x00, 0x00, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x72, 0x73,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        let entries = vec!(
            Dirent {
                ino: 0xaabb,
                offset: 1,
                kind: FileType::Directory,
                name: OsString::from("hello").into(),
            },
            Dirent {
                ino: 0xccdd,
                offset: 2,
                kind: FileType::RegularFile,
                name: OsString::from("world.rs").into(),
            }
        );
        replyhandler.dir(&entries.into(), std::mem::size_of::<u8>()*128, 0);
    }
    
    #[test]
    #[cfg(feature = "abi-7-24")]
    fn reply_directory_plus() {
        // prepare the expected file attribute portion of the message
        // see test::reply_entry() for details
        let mut attr_bytes = Vec::new();
        attr_bytes.extend_from_slice(&[
            0xbb, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
            0xbb, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        #[cfg(target_os = "macos")]
        attr_bytes.extend_from_slice(&[
            0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        attr_bytes.extend_from_slice(&[
            0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00, 0x78, 0x56, 0x00, 0x00,
        ]);
        #[cfg(target_os = "macos")]
        attr_bytes.extend_from_slice([
            0x78, 0x56, 0x00, 0x00,
        ]);
        attr_bytes.extend_from_slice(&[
            0xa4, 0x41, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00,
            0x77, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
        ]);
        #[cfg(target_os = "macos")]
        attr_bytes.extend_from_slice(&[
            0x99, 0x00, 0x00, 0x00,
        ]);
        #[cfg(feature = "abi-7-9")]
        attr_bytes.extend_from_slice(&[
            0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);

        let mut expected = Vec::new();
        // header
        expected.extend_from_slice(&[
            0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
        ]);
        // attr 1
        expected.extend_from_slice(&attr_bytes);
        // dir entry 1
        expected.extend_from_slice(&[
            0xbb, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00,
        ]);
        // attr 2 has a different ino value in two positions
        attr_bytes[0]=0xdd;
        attr_bytes[1]=0xcc;
        attr_bytes[40]=0xdd;
        attr_bytes[41]=0xcc;
        // attr 2 has a different file permission in one position
        let i = if cfg!(target_os = "macos") {113} else {101};
        attr_bytes[i]=0x81;
        expected.extend_from_slice(&attr_bytes);
        // dir entry 2
        expected.extend_from_slice(&[
            0xdd, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x72, 0x73,
        ]);
        // correct the header
        expected[0] = (expected.len()) as u8;
        // test reply will be compared to expected
        let sender = AssertSender {expected};
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr1 = FileAttr {
            ino: 0xaabb,
            size: 0x22,
            blocks: 0x33,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Directory,
            perm: 0o644,
            nlink: 0x55,
            uid: 0x66,
            gid: 0x77,
            rdev: 0x88,
            flags: 0x99,
            blksize: 0xbb,
        };
        let mut attr2 = attr1; //implicit copy
        attr2.ino = 0xccdd;
        attr2.kind = FileType::RegularFile;
        let generation = Some(0xaa);
        let entries = vec!(
            (
                Dirent {
                    ino: 0xaabb,
                    offset: 1,
                    kind: FileType::Directory,
                    name: OsString::from("hello").into(),
                },
                Entry {
                    ino: 0xaabb,
                    generation,
                    file_ttl: ttl,
                    attr: attr1,
                    attr_ttl: ttl,
                }
            ),
            (
                Dirent {
                    ino: 0xccdd,
                    offset: 2,
                    kind: FileType::RegularFile,
                    name: OsString::from("world.rs").into(),
                },
                Entry {
                    ino:0xccdd,
                    generation,
                    file_ttl: ttl,
                    attr: attr2,
                    attr_ttl: ttl,
                }
            )
        );
        replyhandler.dirplus(&entries.into(), std::mem::size_of::<u8>()*4096, 0);
    }

    #[test]
    fn reply_xattr_size() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
                0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.xattr(Xattr::Size(0x12345678));
    }

    #[test]
    fn reply_xattr_data() {
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
            ],
        };
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, sender);
        replyhandler.xattr(Xattr::Data(vec![0x11, 0x22, 0x33, 0x44].into()));
    }

    impl super::ReplySender for SyncSender<()> {
        fn send(&self, _: &[IoSlice<'_>]) -> std::io::Result<()> {
            self.send(()).unwrap();
            Ok(())
        }

        #[cfg(feature = "abi-7-40")]
        fn open_backing(&self, _fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
            unreachable!()
        }
    }

    #[test]
    fn async_reply() {
        let (tx, rx) = sync_channel::<()>(1);
        let replyhandler: ReplyHandler = ReplyHandler::new(0xdeadbeef, tx);
        thread::spawn(move || {
            replyhandler.ok();
        });
        rx.recv().unwrap();
    }
}
