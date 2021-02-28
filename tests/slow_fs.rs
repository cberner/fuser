use fuser::{Filesystem, MountOption, KernelConfig, Request, ReplyStatfs, FileType, ReplyDirectory, FileAttr, ReplyAttr};
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

struct SlowInitFS;

impl Filesystem for SlowInitFS {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), i32> {
        std::thread::sleep(Duration::new(2, 0));
        Ok(())
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
            _ => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != 1 {
            reply.error(libc::ENOENT);
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
        reply.ok();
    }
}

fn main() {
}

#[cfg(test)]
mod tests {
    use fuser::{MountOption, mount};
    use std::ffi::OsStr;
    use crate::SlowInitFS;
    use tempfile::tempdir;
    use std::time::Duration;

    #[test]
    fn test2() {
        let mountpoint = tempdir().unwrap().into_path();
        let start = std::time::SystemTime::now();
        let mount = fuser::spawn_mount(SlowInitFS, &mountpoint, &[OsStr::new("-o"), OsStr::new("auto_unmount")]).unwrap();
        std::thread::sleep(Duration::new(0, 100_000));
        // Check that init hasn't finished
        assert!(start.elapsed().unwrap().as_secs_f64() < 0.5);
        let mut entries = std::fs::read_dir(mountpoint).unwrap();
        assert!(entries.find(|x| x.as_ref().unwrap().file_name().eq("hello.txt")).is_some());
        drop(mount);
    }
}
