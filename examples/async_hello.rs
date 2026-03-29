mod common;

use std::ffi::OsStr;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use std::vec;

use clap::Parser;
use fuser::AsyncFilesystem;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::INodeNo;
use fuser::LockOwner;
use fuser::MountOption;
use fuser::OpenFlags;
use fuser::Request;
use fuser::reply_async::ReadResponse;
use fuser::reply_async::{DirectoryResponse, GetAttrResponse, LookupResponse};

use crate::common::args::CommonArgs;

#[derive(Parser)]
#[command(version, author = "Mattthew Hambrecht")]
struct Args {
    #[clap(flatten)]
    common_args: CommonArgs,
}

const TTL: Duration = Duration::from_secs(1); // 1 second

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: INodeNo::ROOT,
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
};

const HELLO_TXT_CONTENT: &str = "Hello World!\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: INodeNo(2),
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
};

struct HelloFS;

#[async_trait::async_trait]
impl AsyncFilesystem for HelloFS {
    async fn lookup(
        &self,
        _context: &Request,
        parent: INodeNo,
        name: &OsStr,
    ) -> Result<LookupResponse, Errno> {
        if parent == INodeNo::ROOT && name.to_str() == Some("hello.txt") {
            Ok(LookupResponse::new(
                TTL,
                HELLO_TXT_ATTR,
                fuser::Generation(0),
            ))
        } else {
            Err(Errno::ENOENT)
        }
    }

    async fn getattr(
        &self,
        _context: &Request,
        ino: INodeNo,
        _file_handle: Option<FileHandle>,
    ) -> Result<GetAttrResponse, Errno> {
        match ino.0 {
            1 => Ok(GetAttrResponse::new(TTL, HELLO_DIR_ATTR)),
            2 => Ok(GetAttrResponse::new(TTL, HELLO_TXT_ATTR)),
            _ => Err(Errno::ENOENT),
        }
    }

    async fn read(
        &self,
        _context: &Request,
        ino: INodeNo,
        _file_handle: FileHandle,
        offset: u64,
        _size: u32,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
    ) -> Result<ReadResponse, Errno> {
        if ino.0 == 2 {
            Ok(ReadResponse::new(
                HELLO_TXT_CONTENT.as_bytes()[offset.min(HELLO_TXT_CONTENT.len() as u64) as usize..]
                    .to_vec(),
            ))
        } else {
            Err(Errno::ENOENT)
        }
    }

    async fn readdir(
        &self,
        _context: &Request,
        ino: INodeNo,
        _file_handle: FileHandle,
        size: u32,
        offset: u64,
    ) -> Result<DirectoryResponse, Errno> {
        if ino != INodeNo::ROOT {
            return Err(Errno::ENOENT);
        }

        let mut response = DirectoryResponse::new(size as usize);
        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if response.add(INodeNo(entry.0), (i + 1) as u64, entry.1, entry.2) {
                break;
            }
        }
        Ok(response)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    env_logger::init();

    let mut cfg = args.common_args.config();
    cfg.mount_options
        .extend([MountOption::RO, MountOption::FSName("hello".to_string())]);
    fuser::mount_async(HelloFS, &args.common_args.mount_point, &cfg)
        .await
        .unwrap();
}
