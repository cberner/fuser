//! Filesystem operation reply
//!
//! A reply is passed to filesystem operation implementations and must be used to send back the
//! result of an operation. The reply can optionally be sent to another thread to asynchronously
//! work on an operation and provide the result later. Also it allows replying with a block of
//! data without cloning the data. A reply *must always* be used (by calling either `ok()` or
//! `error()` exactly once).

use crate::ll; // too many structs to list
use crate::ll::reply::{DirEntList, DirEntOffset, DirEntry};
#[cfg(feature = "abi-7-21")]
use crate::ll::reply::{DirEntPlusList, DirEntryPlus};
#[cfg(feature = "abi-7-40")]
use crate::{consts::FOPEN_PASSTHROUGH, passthrough::BackingId};
use libc::c_int;
use log::{error, warn};
use std::convert::AsRef;
use std::ffi::OsStr;
use std::fmt;
use std::io::IoSlice;
#[cfg(feature = "abi-7-40")]
use std::os::fd::BorrowedFd;
use std::time::Duration;

#[cfg(target_os = "macos")]
use std::time::SystemTime;

use crate::{FileAttr, FileType};

/// Generic reply callback to send data
pub trait ReplySender: Send + Sync + Unpin + 'static {
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

/// Generic reply trait
pub trait Reply {
    /// Create a new reply for the given request
    fn new<S: ReplySender>(unique: u64, sender: S) -> Self;
}

///
/// Raw reply
///
#[derive(Debug)]
pub(crate) struct ReplyRaw {
    /// Unique id of the request to reply to
    unique: ll::RequestId,
    /// Closure to call for sending the reply
    sender: Option<Box<dyn ReplySender>>,
}

impl Reply for ReplyRaw {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyRaw {
        let sender = Box::new(sender);
        ReplyRaw {
            unique: ll::RequestId(unique),
            sender: Some(sender),
        }
    }
}

impl ReplyRaw {
    /// Reply to a request with the given error code and data. Must be called
    /// only once (the `ok` and `error` methods ensure this by consuming `self`)
    fn send_ll_mut(&mut self, response: &ll::Response<'_>) {
        assert!(self.sender.is_some());
        let sender = self.sender.take().unwrap();
        let res = response.with_iovec(self.unique, |iov| sender.send(iov));
        if let Err(err) = res {
            error!("Failed to send FUSE reply: {err}");
        }
    }
    fn send_ll(mut self, response: &ll::Response<'_>) {
        self.send_ll_mut(response);
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        assert_ne!(err, 0);
        self.send_ll(&ll::Response::new_error(ll::Errno::from_i32(err)));
    }
}

impl Drop for ReplyRaw {
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

///
/// Empty reply
///
#[derive(Debug)]
pub struct ReplyEmpty {
    reply: ReplyRaw,
}

impl Reply for ReplyEmpty {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyEmpty {
        ReplyEmpty {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyEmpty {
    /// Reply to a request with nothing
    pub fn ok(self) {
        self.reply.send_ll(&ll::Response::new_empty());
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Data reply
///
#[derive(Debug)]
pub struct ReplyData {
    reply: ReplyRaw,
}

impl Reply for ReplyData {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyData {
        ReplyData {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyData {
    /// Reply to a request with the given data
    pub fn data(self, data: &[u8]) {
        self.reply.send_ll(&ll::Response::new_slice(data));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Entry reply
///
#[derive(Debug)]
pub struct ReplyEntry {
    reply: ReplyRaw,
}

impl Reply for ReplyEntry {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyEntry {
        ReplyEntry {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyEntry {
    /// Reply to a request with the given entry
    pub fn entry(self, ttl: &Duration, attr: &FileAttr, generation: u64) {
        self.reply.send_ll(&ll::Response::new_entry(
            ll::INodeNo(attr.ino),
            ll::Generation(generation),
            &attr.into(),
            *ttl,
            *ttl,
        ));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Attribute Reply
///
#[derive(Debug)]
pub struct ReplyAttr {
    reply: ReplyRaw,
}

impl Reply for ReplyAttr {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyAttr {
        ReplyAttr {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyAttr {
    /// Reply to a request with the given attribute
    pub fn attr(self, ttl: &Duration, attr: &FileAttr) {
        self.reply
            .send_ll(&ll::Response::new_attr(ttl, &attr.into()));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// XTimes Reply
///
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct ReplyXTimes {
    reply: ReplyRaw,
}

#[cfg(target_os = "macos")]
impl Reply for ReplyXTimes {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyXTimes {
        ReplyXTimes {
            reply: Reply::new(unique, sender),
        }
    }
}

#[cfg(target_os = "macos")]
impl ReplyXTimes {
    /// Reply to a request with the given xtimes
    pub fn xtimes(self, bkuptime: SystemTime, crtime: SystemTime) {
        self.reply
            .send_ll(&ll::Response::new_xtimes(bkuptime, crtime))
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Open Reply
///
#[derive(Debug)]
pub struct ReplyOpen {
    reply: ReplyRaw,
}

impl Reply for ReplyOpen {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyOpen {
        ReplyOpen {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyOpen {
    /// Reply to a request with the given open result
    /// # Panics
    /// When attempting to use kernel passthrough. Use `opened_passthrough()` instead.
    pub fn opened(self, fh: u64, flags: u32) {
        #[cfg(feature = "abi-7-40")]
        assert_eq!(flags & FOPEN_PASSTHROUGH, 0);
        self.reply
            .send_ll(&ll::Response::new_open(ll::FileHandle(fh), flags, 0));
    }

    /// Registers a fd for passthrough, returning a `BackingId`.  Once you have the backing ID,
    /// you can pass it as the 3rd parameter of `OpenReply::opened_passthrough()`.  This is done in
    /// two separate steps because it may make sense to reuse backing IDs (to avoid having to
    /// repeatedly reopen the underlying file or potentially keep thousands of fds open).
    /// # Errors
    /// Propagates errors due to communicating with the fuse device.
    /// # Panics
    /// Panics if this reply object has already been used.
    #[cfg(feature = "abi-7-40")]
    pub fn open_backing(&self, fd: impl std::os::fd::AsFd) -> std::io::Result<BackingId> {
        self.reply.sender.as_ref().unwrap().open_backing(fd.as_fd())
    }

    /// Reply to a request with an opened backing id.  Call `ReplyOpen::open_backing()` to get one of
    /// these.
    #[cfg(feature = "abi-7-40")]
    pub fn opened_passthrough(self, fh: u64, flags: u32, backing_id: &BackingId) {
        self.reply.send_ll(&ll::Response::new_open(
            ll::FileHandle(fh),
            flags | FOPEN_PASSTHROUGH,
            backing_id.backing_id,
        ));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Write Reply
///
#[derive(Debug)]
pub struct ReplyWrite {
    reply: ReplyRaw,
}

impl Reply for ReplyWrite {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyWrite {
        ReplyWrite {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyWrite {
    /// Reply to a request with the number of bytes written
    pub fn written(self, size: u32) {
        self.reply.send_ll(&ll::Response::new_write(size));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Statfs Reply
///
#[derive(Debug)]
pub struct ReplyStatfs {
    reply: ReplyRaw,
}

impl Reply for ReplyStatfs {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyStatfs {
        ReplyStatfs {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyStatfs {
    /// Reply to a statfs request with filesystem information
    #[allow(clippy::too_many_arguments)]
    pub fn statfs(
        self,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        bsize: u32,
        namelen: u32,
        frsize: u32,
    ) {
        self.reply.send_ll(&ll::Response::new_statfs(
            blocks, bfree, bavail, files, ffree, bsize, namelen, frsize,
        ));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Create reply
///
#[derive(Debug)]
pub struct ReplyCreate {
    reply: ReplyRaw,
}

impl Reply for ReplyCreate {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyCreate {
        ReplyCreate {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyCreate {
    /// Reply to a request with a newly created file entry and its newly open file handle
    /// # Panics
    /// When attempting to use kernel passthrough. Use `opened_passthrough()` instead.
    pub fn created(self, ttl: &Duration, attr: &FileAttr, generation: u64, fh: u64, flags: u32) {
        #[cfg(feature = "abi-7-40")]
        assert_eq!(flags & FOPEN_PASSTHROUGH, 0);
        self.reply.send_ll(&ll::Response::new_create(
            ttl,
            &attr.into(),
            ll::Generation(generation),
            ll::FileHandle(fh),
            flags,
            0,
        ));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Lock Reply
///
#[derive(Debug)]
pub struct ReplyLock {
    reply: ReplyRaw,
}

impl Reply for ReplyLock {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyLock {
        ReplyLock {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyLock {
    /// Reply to a request with a file lock
    pub fn locked(self, start: u64, end: u64, typ: i32, pid: u32) {
        self.reply.send_ll(&ll::Response::new_lock(&ll::Lock {
            range: (start, end),
            typ,
            pid,
        }));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Bmap Reply
///
#[derive(Debug)]
pub struct ReplyBmap {
    reply: ReplyRaw,
}

impl Reply for ReplyBmap {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyBmap {
        ReplyBmap {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyBmap {
    /// Reply to a request with a bmap
    pub fn bmap(self, block: u64) {
        self.reply.send_ll(&ll::Response::new_bmap(block));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Ioctl Reply
///
#[derive(Debug)]
pub struct ReplyIoctl {
    reply: ReplyRaw,
}

impl Reply for ReplyIoctl {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyIoctl {
        ReplyIoctl {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyIoctl {
    /// Reply to a request with an ioctl
    pub fn ioctl(self, result: i32, data: &[u8]) {
        self.reply
            .send_ll(&ll::Response::new_ioctl(result, &[IoSlice::new(data)]));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Poll Reply
///
#[derive(Debug)]
pub struct ReplyPoll {
    reply: ReplyRaw,
}

impl Reply for ReplyPoll {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyPoll {
        ReplyPoll {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyPoll {
    /// Reply to a request with ready poll events
    pub fn poll(self, revents: u32) {
        self.reply.send_ll(&ll::Response::new_poll(revents));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Directory reply
///
#[derive(Debug)]
pub struct ReplyDirectory {
    reply: ReplyRaw,
    data: DirEntList,
}

impl ReplyDirectory {
    /// Creates a new `ReplyDirectory` with a specified buffer size.
    pub fn new<S: ReplySender>(unique: u64, sender: S, size: usize) -> ReplyDirectory {
        ReplyDirectory {
            reply: Reply::new(unique, sender),
            data: DirEntList::new(size),
        }
    }

    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    #[must_use]
    pub fn add<T: AsRef<OsStr>>(&mut self, ino: u64, offset: i64, kind: FileType, name: T) -> bool {
        let name = name.as_ref();
        self.data.push(&DirEntry::new(
            ll::INodeNo(ino),
            DirEntOffset(offset),
            kind,
            name,
        ))
    }

    /// Reply to a request with the filled directory buffer
    pub fn ok(self) {
        self.reply.send_ll(&self.data.into());
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// `DirectoryPlus` reply
///
#[cfg(feature = "abi-7-21")]
#[derive(Debug)]
pub struct ReplyDirectoryPlus {
    reply: ReplyRaw,
    buf: DirEntPlusList,
}

#[cfg(feature = "abi-7-21")]
impl ReplyDirectoryPlus {
    /// Creates a new `ReplyDirectory` with a specified buffer size.
    pub fn new<S: ReplySender>(unique: u64, sender: S, size: usize) -> ReplyDirectoryPlus {
        ReplyDirectoryPlus {
            reply: Reply::new(unique, sender),
            buf: DirEntPlusList::new(size),
        }
    }

    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    pub fn add<T: AsRef<OsStr>>(
        &mut self,
        ino: u64,
        offset: i64,
        name: T,
        ttl: &Duration,
        attr: &FileAttr,
        generation: u64,
    ) -> bool {
        let name = name.as_ref();
        self.buf.push(&DirEntryPlus::new(
            ll::INodeNo(ino),
            ll::Generation(generation),
            DirEntOffset(offset),
            name,
            *ttl,
            attr.into(),
            *ttl,
        ))
    }

    /// Reply to a request with the filled directory buffer
    pub fn ok(self) {
        self.reply.send_ll(&self.buf.into());
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Xattr reply
///
#[derive(Debug)]
pub struct ReplyXattr {
    reply: ReplyRaw,
}

impl Reply for ReplyXattr {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyXattr {
        ReplyXattr {
            reply: Reply::new(unique, sender),
        }
    }
}

impl ReplyXattr {
    /// Reply to a request with the size of an extended attribute
    pub fn size(self, size: u32) {
        self.reply.send_ll(&ll::Response::new_xattr_size(size));
    }

    /// Reply to a request with the data of an extended attribute
    pub fn data(self, data: &[u8]) {
        self.reply.send_ll(&ll::Response::new_slice(data));
    }

    /// Reply to a request with the given error code.
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

///
/// Lseek Reply
///
#[cfg(feature = "abi-7-24")]
#[derive(Debug)]
pub struct ReplyLseek {
    reply: ReplyRaw,
}

#[cfg(feature = "abi-7-24")]
impl Reply for ReplyLseek {
    fn new<S: ReplySender>(unique: u64, sender: S) -> ReplyLseek {
        ReplyLseek {
            reply: Reply::new(unique, sender),
        }
    }
}

#[cfg(feature = "abi-7-24")]
impl ReplyLseek {
    /// Reply to a request with seeked offset
    pub fn offset(self, offset: i64) {
        self.reply.send_ll(&ll::Response::new_lseek(offset));
    }

    /// Reply to a request with the given error code
    pub fn error(self, err: c_int) {
        self.reply.error(err);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{FileAttr, FileType};
    use std::io::IoSlice;
    use std::sync::mpsc::{SyncSender, sync_channel};
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};
    use zerocopy::{Immutable, IntoBytes};

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
                v.extend_from_slice(x);
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
        let reply: ReplyRaw = Reply::new(0xdeadbeef, sender);
        reply.send_ll(&ll::Response::new_data(data.as_bytes()));
    }

    #[test]
    fn reply_error() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0xbe, 0xff, 0xff, 0xff, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyRaw = Reply::new(0xdeadbeef, sender);
        reply.error(66);
    }

    #[test]
    fn reply_empty() {
        let sender = AssertSender {
            expected: vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        let reply: ReplyEmpty = Reply::new(0xdeadbeef, sender);
        reply.ok();
    }

    #[test]
    fn reply_data() {
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
            ],
        };
        let reply: ReplyData = Reply::new(0xdeadbeef, sender);
        reply.data(&[0xde, 0xad, 0xbe, 0xef]);
    }

    macro_rules! default_attr_struct {
        () => {{
            let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
            FileAttr {
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
            }
        }};
    }

    macro_rules! default_attr_bytes {
        () => {{
            let mut expected = Vec::new();
            expected.extend_from_slice(&[
                // inode attributes
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ino */
                0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* size */
                0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* blocks */
            ]);
            expected.extend_from_slice(&[
                // timestamps (s)
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* atime */
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* mtime */
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ctime */
            ]);
            #[cfg(target_os = "macos")]
            expected.extend_from_slice(&[
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* crtime */
            ]);
            expected.extend_from_slice(&[
                // timestamps (nanos)
                0x78, 0x56, 0x00, 0x00, /* atime */
                0x78, 0x56, 0x00, 0x00, /* mtime */
                0x78, 0x56, 0x00, 0x00, /* ctime */
            ]);
            #[cfg(target_os = "macos")]
            expected.extend_from_slice(&[0x78, 0x56, 0x00, 0x00 /* crtime */]);
            expected.extend_from_slice(&[
                // access attributes
                0xa4, 0x81, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x77, 0x00,
                0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
            ]);
            #[cfg(target_os = "macos")]
            expected.extend_from_slice(&[
                // macos flags
                0x99, 0x00, 0x00, 0x00,
            ]);
            expected.extend_from_slice(&[
                // block size
                0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
            // return
            expected
        }};
    }

    #[test]
    fn reply_entry() {
        // prepare the expected message
        let mut expected = Vec::new();
        expected.extend_from_slice(&[
            // FUSE header
            0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* size */
            0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, /* request id */
        ]);
        expected.extend_from_slice(&[
            // ino
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        expected.extend_from_slice(&[
            // generation
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        expected.extend_from_slice(&[
            // file ttl
            0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* seconds */
        ]);
        expected.extend_from_slice(&[
            // attr ttl
            0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* whole seconds */
            0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, /* nanoseconds */
        ]);
        expected.extend(default_attr_bytes!().iter());
        // correct the header using the actual length
        expected[0] = (expected.len()) as u8;
        // test reply will be compare with the expected message
        let sender = AssertSender { expected };
        // prepare the test reply
        let reply: ReplyEntry = Reply::new(0xdeadbeef, sender);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = default_attr_struct!();
        // send the test reply
        reply.entry(&ttl, &attr, 0xaa);
    }

    #[test]
    fn reply_attr() {
        let mut expected = vec![
            // FUSE header
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* size */
            0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, /* request id */
        ];
        expected.extend_from_slice(&[
            // ttl
            0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* seconds */
            0x21, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* nanoseconds */
        ]);
        expected.extend(default_attr_bytes!().iter());

        // correct size field of header
        expected[0] = expected.len() as u8;

        let sender = AssertSender { expected };
        let reply: ReplyAttr = Reply::new(0xdeadbeef, sender);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = default_attr_struct!();
        reply.attr(&ttl, &attr);
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
        let reply: ReplyXTimes = Reply::new(0xdeadbeef, sender);
        let time = UNIX_EPOCH + Duration::new(0x1234, 0x5678);
        reply.xtimes(time, time);
    }

    macro_rules! default_open_tuple {
        (with_backing) => {{
            (
                /* fh */ 0x1122,
                /* flags */ 0x33,
                /* backing_id*/ 0x44 as u32,
            )
        }};
        () => {{
            (/* fh */ 0x1122, /* flags */ 0x33)
        }};
    }

    macro_rules! default_open_bytes {
        (with_backing) => {
            default_open_bytes!(0x44, 0x33 | (1 << 7))
        };
        () => {
            default_open_bytes!(0x00, 0x33)
        };
        ($id:expr, $flag:expr) => {{
            let mut expected = vec![
                // file handle
                0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            expected.extend_from_slice(&[
                // flags
                $flag, 0x00, 0x00, 0x00,
            ]);
            expected.extend_from_slice(&[
                // backing id
                $id, 0x00, 0x00, 0x00,
            ]);
            // return
            expected
        }};
    }
    #[test]
    fn reply_open() {
        let mut expected = vec![
            // FUSE header
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size
            0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, // request id
        ];
        expected.extend(&default_open_bytes!());
        let sender = AssertSender { expected };
        let reply: ReplyOpen = Reply::new(0xdeadbeef, sender);
        let (fh, flags) = default_open_tuple!();
        reply.opened(fh, flags);
    }
    #[test]
    #[cfg(feature = "abi-7-40")]
    fn reply_open_passthrough() {
        let mut expected = vec![
            // FUSE header
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size
            0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, // request id
        ];
        expected.extend(&default_open_bytes!(with_backing));
        let sender = AssertSender { expected };
        let reply: ReplyOpen = Reply::new(0xdeadbeef, sender);
        let (fh, flags, backing_id) = default_open_tuple!(with_backing);
        let backing = BackingId {
            channel: std::sync::Weak::new(),
            backing_id,
        };
        reply.opened_passthrough(fh, flags, &backing);
    }
    #[test]
    fn reply_write() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyWrite = Reply::new(0xdeadbeef, sender);
        reply.written(0x1122);
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
        let reply: ReplyStatfs = Reply::new(0xdeadbeef, sender);
        reply.statfs(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);
    }

    #[test]
    fn reply_create() {
        let mut expected = vec![
            // FUSE header
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size
            0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, // request id
        ];
        expected.extend_from_slice(&[
            // ino
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        expected.extend_from_slice(&[
            // generation
            0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        expected.extend_from_slice(&[
            // file ttl
            0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* seconds */
        ]);
        expected.extend_from_slice(&[
            // attr ttl
            0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* whole seconds */
            0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, /* nanoseconds */
        ]);
        expected.extend(&default_attr_bytes!());
        expected.extend(&default_open_bytes!());
        expected[0] = (expected.len()) as u8;

        let sender = AssertSender { expected };
        let reply: ReplyCreate = Reply::new(0xdeadbeef, sender);
        let ttl = Duration::new(0x8765, 0x4321);
        let attr = default_attr_struct!();
        let (fh, flags) = default_open_tuple!();
        reply.created(&ttl, &attr, 0xaa, fh, flags);
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
        let reply: ReplyLock = Reply::new(0xdeadbeef, sender);
        reply.locked(0x11, 0x22, 0x33, 0x44);
    }

    #[test]
    fn reply_bmap() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
                0x00, 0x00, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply: ReplyBmap = Reply::new(0xdeadbeef, sender);
        reply.bmap(0x1234);
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
        let mut reply = ReplyDirectory::new(0xdeadbeef, sender, 4096);
        assert!(!reply.add(0xaabb, 1, FileType::Directory, "hello"));
        assert!(!reply.add(0xccdd, 2, FileType::RegularFile, "world.rs"));
        reply.ok();
    }

    #[test]
    #[cfg(feature = "abi-7-21")]
    fn reply_directory_plus() {
        // prepare the expected file attribute portion of the message
        // see test::reply_entry() for details
        let mut entry_bytes = Vec::new();
        entry_bytes.extend_from_slice(&[
            0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x65, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x87, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00, 0x21, 0x43, 0x00, 0x00,
        ]);
        let mut attr_bytes = default_attr_bytes!();

        let mut expected = Vec::new();

        expected.extend_from_slice(&[
            // FUSE header
            0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
            0x00, 0x00,
        ]);

        /* ------ file 1 ------- */
        // entry 1 and attr 1 get a specific ino value
        entry_bytes[0] = 0xbb;
        entry_bytes[1] = 0xaa;
        attr_bytes[0] = 0xbb;
        attr_bytes[1] = 0xaa;
        // entry 1 and attr 1 have the directory type
        let i = if cfg!(target_os = "macos") { 73 } else { 61 };
        attr_bytes[i] = 0x41;
        expected.extend_from_slice(&entry_bytes);
        expected.extend_from_slice(&attr_bytes);
        // dirent 1
        // see test::reply_directory() for details
        expected.extend_from_slice(&[
            0xbb, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c,
            0x6f, 0x00, 0x00, 0x00,
        ]);

        /* ------ file 2 ------- */
        let mut attr_bytes = default_attr_bytes!();
        // entry 2 and attr 2 get a specific ino value
        entry_bytes[0] = 0xdd;
        entry_bytes[1] = 0xcc;
        attr_bytes[0] = 0xdd;
        attr_bytes[1] = 0xcc;
        expected.extend_from_slice(&entry_bytes);
        expected.extend_from_slice(&attr_bytes);
        // dirent 2
        expected.extend_from_slice(&[
            0xdd, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x77, 0x6f, 0x72, 0x6c,
            0x64, 0x2e, 0x72, 0x73,
        ]);
        // correct the header
        expected[0] = (expected.len()) as u8;
        // test reply will be compared to expected
        let sender = AssertSender { expected };
        let mut reply =
            ReplyDirectoryPlus::new(0xdeadbeef, sender, std::mem::size_of::<u8>() * 4096);
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
        let generation = 0xaa;
        assert!(!reply.add(0xaabb, 1, "hello", &ttl, &attr1, generation,));
        assert!(!reply.add(0xccdd, 2, "world.rs", &ttl, &attr2, generation,));
        reply.ok();
    }

    #[test]
    fn reply_xattr_size() {
        let sender = AssertSender {
            expected: vec![
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
                0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
            ],
        };
        let reply = ReplyXattr::new(0xdeadbeef, sender);
        reply.size(0x12345678);
    }

    #[test]
    fn reply_xattr_data() {
        let sender = AssertSender {
            expected: vec![
                0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
            ],
        };
        let reply = ReplyXattr::new(0xdeadbeef, sender);
        reply.data(&[0x11, 0x22, 0x33, 0x44]);
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
    fn threaded_reply() {
        let (tx, rx) = sync_channel::<()>(1);
        let reply: ReplyEmpty = Reply::new(0xdeadbeef, tx);
        thread::spawn(move || {
            reply.ok();
        });
        rx.recv().unwrap();
    }
}
