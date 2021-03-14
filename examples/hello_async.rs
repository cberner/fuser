#![allow(clippy::too_many_arguments)]

use fuser::async_api::{Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request};
#[cfg(feature = "async_impl")]
use fuser::MountOption;
use fuser::{FileAttr, FileType};

use libc::ENOENT;
#[cfg(feature = "async_impl")]
use std::env;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1); // 1 second

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
    padding: 0,
};

const HELLO_TXT_CONTENT: &str = "Hello World!\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 13,
    blocks: 1,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
    padding: 0,
};

struct HelloFS;

#[async_trait::async_trait]
impl Filesystem for HelloFS {
    async fn lookup(&self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &HELLO_TXT_ATTR, 0).await;
        } else {
            reply.error(ENOENT).await;
        }
    }

    async fn getattr(&self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match ino {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR).await,
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR).await,
            _ => reply.error(ENOENT).await,
        }
    }

    async fn read(
        &self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == 2 {
            reply
                .data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..])
                .await;
        } else {
            reply.error(ENOENT).await;
        }
    }

    async fn readdir(
        &self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != 1 {
            reply.error(ENOENT).await;
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok().await;
    }
}

#[cfg(feature = "async_tokio")]
#[tokio::main]
async fn main() {
    env_logger::init();
    let mountpoint = env::args_os().nth(1).unwrap();
    let mut options = vec![MountOption::RO, MountOption::FSName("hello".to_string())];
    if let Some(auto_unmount) = env::args_os().nth(2) {
        if auto_unmount.eq("--auto_unmount") {
            options.push(MountOption::AutoUnmount);
        }
    }
    fuser::async_api::mount2(HelloFS, 5, mountpoint, &options)
        .await
        .unwrap();
}

#[cfg(not(feature = "async_impl"))]
fn main() {
    panic!("No async implementation enabled.")
}
