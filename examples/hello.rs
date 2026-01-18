use std::ffi::OsStr;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use clap::Arg;
use clap::ArgAction;
use clap::Command;
use clap::crate_version;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::Filesystem;
use fuser::INodeNo;
use fuser::MountOption;
use fuser::ReadFlags;
use fuser::ReplyAttr;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEntry;
use fuser::Request;

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

impl Filesystem for HelloFS {
    fn lookup(&mut self, _req: &Request<'_>, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if u64::from(parent) == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &HELLO_TXT_ATTR, fuser::Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(
        &mut self,
        _req: &Request<'_>,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        match u64::from(ino) {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: INodeNo,
        _fh: FileHandle,
        offset: i64,
        _size: u32,
        _flags: ReadFlags,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if u64::from(ino) == 2 {
            reply.data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: INodeNo,
        _fh: FileHandle,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if u64::from(ino) != 1 {
            reply.error(Errno::ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(INodeNo(entry.0), (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
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
    fuser::mount2(HelloFS, mountpoint, &options).unwrap();
}
