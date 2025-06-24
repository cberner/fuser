// This example requires fuse 7.11 or later. Run with:
//
//   cargo run --example ioctl --features abi-7-11 /tmp/foobar

use clap::{crate_version, Arg, ArgAction, Command};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, RequestMeta, Entry, Attr, Ioctl, Errno, DirEntry,
};
use log::debug;
use std::ffi::{OsStr, OsString};
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1); // 1 second

struct FiocFS {
    content: Vec<u8>,
    root_attr: FileAttr,
    fioc_file_attr: FileAttr,
}

impl FiocFS {
    fn new() -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let root_attr = FileAttr {
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
            uid,
            gid,
            rdev: 0,
            flags: 0,
            blksize: 512,
        };

        let fioc_file_attr = FileAttr {
            ino: 2,
            size: 0,
            blocks: 1,
            atime: UNIX_EPOCH, // 1970-01-01 00:00:00
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            flags: 0,
            blksize: 512,
        };

        Self {
            content: vec![],
            root_attr,
            fioc_file_attr,
        }
    }
}

impl Filesystem for FiocFS {
    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: OsString) -> Result<Entry, Errno> {
        if parent == 1 && name == OsStr::new("fioc") {
            Ok(Entry {
                attr: self.fioc_file_attr,
                ttl: TTL,
                generation: 0,
            })
        } else {
            Err(Errno::ENOENT)
        }
    }

    fn getattr(&mut self, _req: RequestMeta, ino: u64, _fh: Option<u64>) -> Result<Attr, Errno> {
        match ino {
            1 => Ok(Attr { attr: self.root_attr, ttl: TTL,}),
            2 => Ok(Attr { attr: self.fioc_file_attr, ttl: TTL,}),
            _ => Err(Errno::ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
    ) -> Result<Vec<u8>, Errno> {
        if ino == 2 {
            Ok(self.content[offset as usize..].to_vec())
        } else {
            Err(Errno::ENOENT)
        }
    }

    fn readdir(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64,
        offset: i64,
        _max_bytes: u32,
    ) -> Result<Vec<DirEntry>, Errno> {
        if ino != 1 {
            return Err(Errno::ENOENT);
        }

        let entries = vec![
            DirEntry { ino: 1, offset: 1, kind: FileType::Directory, name: OsString::from(".") },
            DirEntry { ino: 1, offset: 2, kind: FileType::Directory, name: OsString::from("..") },
            DirEntry { ino: 2, offset: 3, kind: FileType::RegularFile, name: OsString::from("fioc") },
        ];

        let mut result = Vec::new();
        for entry in entries.into_iter().skip(offset as usize) {
            // example loop where additional logic could be inserted
            result.push(entry);
        }
        Ok(result)
    }

    #[cfg(feature = "abi-7-11")]
    fn ioctl(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64,
        _flags: u32,
        cmd: u32,
        in_data: Vec<u8>,
        _out_size: u32,
    ) -> Result<Ioctl, Errno> {
        if ino != 2 {
            return Err(Errno::EINVAL);
        }

        const FIOC_GET_SIZE: u64 = nix::request_code_read!('E', 0, std::mem::size_of::<usize>());
        const FIOC_SET_SIZE: u64 = nix::request_code_write!('E', 1, std::mem::size_of::<usize>());

        match cmd.into() {
            FIOC_GET_SIZE => {
                let size_bytes = self.content.len().to_ne_bytes();
                Ok(Ioctl {
                    result: 0,
                    data: size_bytes.to_vec(),
                })
            }
            FIOC_SET_SIZE => {
                let new_size = usize::from_ne_bytes(in_data.as_slice().try_into().unwrap());
                self.content = vec![0_u8; new_size];
                Ok(Ioctl {
                    result: 0,
                    data: vec![],
                })
            }
            _ => {
                debug!("unknown ioctl: {}", cmd);
                Err(Errno::EINVAL)
            }
        }
    }
}

fn main() {
    let matches = Command::new("hello")
        .version(crate_version!())
        .author("Colin Marc")
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
    let mut options = vec![MountOption::FSName("fioc".to_string())];
    if matches.get_flag("auto_unmount") {
        options.push(MountOption::AutoUnmount);
    }
    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    let fs = FiocFS::new();
    fuser::mount2(fs, mountpoint, &options).unwrap();
}
