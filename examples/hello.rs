use clap::{crate_version, Arg, ArgAction, Command};
use fuser::{
    Filesystem, MountOption, Attr, DirEntry,
    Entry, Errno, RequestMeta, FileType, FileAttr
};
use std::ffi::{OsStr, OsString};
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

impl Filesystem for HelloFS {
    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: OsString) -> Result<Entry, Errno> {
        if parent == 1 && name == OsStr::new("hello.txt") {
            Ok(Entry{attr: HELLO_TXT_ATTR, ttl: TTL, generation: 0})
        } else {
            Err(Errno::ENOENT)
        }
    }

    fn getattr(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: Option<u64>,
    ) -> Result<Attr, Errno> {
        match ino {
            1 => Ok(Attr{attr: HELLO_DIR_ATTR, ttl: TTL,}),
            2 => Ok(Attr{attr: HELLO_TXT_ATTR, ttl: TTL,}),
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
            Ok(HELLO_TXT_CONTENT.as_bytes()[offset as usize..].to_vec())
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
            DirEntry { ino: 2, offset: 3, kind: FileType::RegularFile, name: OsString::from("hello.txt") },
        ];

        let mut result = Vec::new();
        for entry in entries.into_iter().skip(offset as usize) {
            // example loop where additional logic could be inserted
            result.push(entry);
        }
        Ok(result)
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

#[cfg(test)]
mod test {
    use fuser::{Filesystem, RequestMeta, Errno, FileType};
    use std::ffi::OsString;

    fn dummy_meta() -> RequestMeta {
        RequestMeta { unique: 0, uid: 1000, gid: 1000, pid: 2000 }
    }

    #[test]
    fn test_lookup_hello_txt() {
        let mut hellofs = super::HelloFS {};
        let req = dummy_meta();
        let result = hellofs.lookup(req, 1, OsString::from("hello.txt"));
        assert!(result.is_ok(), "Lookup for hello.txt should succeed");
        if let Ok(entry) = result {
            assert_eq!(entry.attr.ino, 2, "Lookup should return inode 2 for hello.txt");
            assert_eq!(entry.attr.kind, FileType::RegularFile, "hello.txt should be a regular file");
            assert_eq!(entry.attr.perm, 0o644, "hello.txt should have permissions 0o644");
        }
    }

    #[test]
    fn test_read_hello_txt() {
        let mut hellofs = super::HelloFS {};
        let req = dummy_meta();
        let result = hellofs.read(req, 2, 0, 0, 13, 0, None);
        assert!(result.is_ok(), "Read for hello.txt should succeed");
        if let Ok(content) = result {
            assert_eq!(String::from_utf8_lossy(&content), "Hello World!\n", "Content of hello.txt should be 'Hello World!\\n'");
        }
    }

    #[test]
    fn test_readdir_root() {
        let mut hellofs = super::HelloFS {};
        let req = dummy_meta();
        let result = hellofs.readdir(req, 1, 0, 0, 4096);
        assert!(result.is_ok(), "Readdir on root should succeed");
        if let Ok(entries) = result {
            assert_eq!(entries.len(), 3, "Root directory should contain exactly 3 entries");
            assert_eq!(entries[0].name, OsString::from("."), "First entry should be '.'");
            assert_eq!(entries[0].ino, 1, "Inode for '.' should be 1");
            assert_eq!(entries[1].name, OsString::from(".."), "Second entry should be '..'");
            assert_eq!(entries[1].ino, 1, "Inode for '..' should be 1");
            assert_eq!(entries[2].name, OsString::from("hello.txt"), "Third entry should be 'hello.txt'");
            assert_eq!(entries[2].ino, 2, "Inode for 'hello.txt' should be 2");
        }
    }

    #[test]
    fn test_create_fails_readonly() {
        let mut hellofs = super::HelloFS {};
        let req = dummy_meta();
        let result = hellofs.create(req, 1, OsString::from("newfile.txt"), 0o644, 0, 0);
        assert!(result.is_err(), "Create should fail for read-only filesystem");
        if let Err(e) = result {
            assert_eq!(e, Errno::ENOSYS, "Create should return ENOSYS for unsupported operation");
        }
    }
}
