use clap::{Arg, ArgAction, Command, crate_version};
use fuser::experimental::{
    AsyncFilesystem, DirEntListBuilder, GetAttrResponse, LookupResponse, RequestContext,
    TokioAdapter,
};
use fuser::{FileAttr, FileType, MountOption, experimental};
use libc::ENOENT;
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
};

struct HelloFS;

#[async_trait::async_trait]
impl AsyncFilesystem for HelloFS {
    async fn lookup(
        &self,
        _context: &RequestContext,
        parent: u64,
        name: &OsStr,
    ) -> experimental::Result<LookupResponse> {
        if parent == 1 && name.to_str() == Some("hello.txt") {
            Ok(LookupResponse::new(TTL, HELLO_TXT_ATTR, 0))
        } else {
            Err(ENOENT)
        }
    }

    async fn getattr(
        &self,
        _context: &RequestContext,
        ino: u64,
        _file_handle: Option<u64>,
    ) -> experimental::Result<GetAttrResponse> {
        match ino {
            1 => Ok(GetAttrResponse::new(TTL, HELLO_DIR_ATTR)),
            2 => Ok(GetAttrResponse::new(TTL, HELLO_TXT_ATTR)),
            _ => Err(ENOENT),
        }
    }

    async fn read(
        &self,
        _context: &RequestContext,
        ino: u64,
        _file_handle: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
        out_data: &mut Vec<u8>,
    ) -> experimental::Result<()> {
        if ino == 2 {
            out_data.extend_from_slice(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
            Ok(())
        } else {
            Err(ENOENT)
        }
    }

    async fn readdir(
        &self,
        _context: &RequestContext,
        ino: u64,
        _file_handle: u64,
        offset: i64,
        mut builder: DirEntListBuilder<'_>,
    ) -> experimental::Result<()> {
        if ino != 1 {
            return Err(ENOENT);
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if builder.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        Ok(())
    }
}

fn main() {
    let matches = Command::new("hello")
        .version(crate_version!())
        .author("Christopher Berner")
        .arg(
            Arg::new("MOUNT_POINT")
                .required(true)
                .index(1)
                .help("Act as a client, and mount FUSE at given path"),
        )
        .arg(
            Arg::new("auto_unmount")
                .long("auto_unmount")
                .action(ArgAction::SetTrue)
                .help("Automatically unmount on process exit"),
        )
        .arg(
            Arg::new("allow-root")
                .long("allow-root")
                .action(ArgAction::SetTrue)
                .help("Allow root user to access filesystem"),
        )
        .get_matches();
    env_logger::init();
    let mountpoint = matches.get_one::<String>("MOUNT_POINT").unwrap();
    let mut options = vec![MountOption::RO, MountOption::FSName("hello".to_string())];
    if matches.get_flag("auto_unmount") {
        options.push(MountOption::AutoUnmount);
    }
    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }
    fuser::mount2(TokioAdapter::new(HelloFS), mountpoint, &options).unwrap();
}
