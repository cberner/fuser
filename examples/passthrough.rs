// This example requires fuse 7.40 or later. Run with:
//
//   cargo run --example passthrough /tmp/foobar

mod common;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use clap::Parser;
use fuser::BackingId;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::Filesystem;
use fuser::FopenFlags;
use fuser::INodeNo;
#[cfg(not(target_os = "macos"))]
use fuser::InitFlags;
use fuser::KernelConfig;
use fuser::LockOwner;
use fuser::MountOption;
use fuser::OpenFlags;
use fuser::ReplyAttr;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEmpty;
use fuser::ReplyEntry;
use fuser::ReplyOpen;
use fuser::Request;

#[derive(Parser)]
#[command(version, author = "Allison Karlitskaya")]
struct Args {
    #[clap(flatten)]
    common_args: CommonArgs,
}

const TTL: Duration = Duration::from_secs(1); // 1 second

/// `BackingCache` is an example of how a filesystem might manage `BackingId` objects for fd
/// passthrough.  The idea is to avoid creating more than one `BackingId` object per file at a time.
///
/// We do this by keeping a weak "by inode" hash table mapping inode numbers to `BackingId`.  If a
/// `BackingId` already exists, we use it.  Otherwise, we create it.  This is not enough to keep the
/// `BackingId` alive, though.  For each `Filesystem::open()` request we allocate a fresh 'fh'
/// (monotonically increasing u64, `next_fh`, never recycled) and use that to keep a *strong*
/// reference on the `BackingId` for that open.  We drop it from the table on `Filesystem::release()`,
/// which means the `BackingId` will be dropped in the kernel when the last user of it closes.
///
/// In this way, if a request to open a file comes in and the file is already open, we'll reuse the
/// `BackingId`, but as soon as all references are closed, the `BackingId` will be dropped.
///
/// It's left as an exercise to the reader to implement an active cleanup of the `by_inode` table, if
/// desired, but our little example filesystem only contains one file. :)
#[derive(Debug, Default)]
struct BackingCache {
    by_handle: HashMap<u64, Arc<Backing>>,
    by_inode: HashMap<INodeNo, Weak<Backing>>,
    next_fh: u64,
}

/// A backing file and the `BackingId` the kernel knows it by.
///
/// The file is kept open as well as being handed to the kernel, because the kernel still sends
/// some reads of a passthrough file to `Filesystem::read()` - those for `readahead(2)`, for
/// example - and they are answered from it.
#[derive(Debug)]
struct Backing {
    id: BackingId,
    file: File,
}

impl BackingCache {
    fn next_fh(&mut self) -> u64 {
        self.next_fh += 1;
        self.next_fh
    }

    /// Gets the existing `Backing` for `ino` if it exists, or calls `callback` to create it.
    ///
    /// Returns a unique file handle and the `Backing` (possibly shared, possibly new).  The
    /// returned file handle should be `put()` when you're done with it.
    fn get_or(
        &mut self,
        ino: INodeNo,
        callback: impl Fn() -> std::io::Result<Backing>,
    ) -> std::io::Result<(u64, Arc<Backing>)> {
        let fh = self.next_fh();

        let backing = if let Some(backing) = self.by_inode.get(&ino).and_then(Weak::upgrade) {
            eprintln!("HIT! reusing {:?}", backing.id);
            backing
        } else {
            let backing = Arc::new(callback()?);
            self.by_inode.insert(ino, Arc::downgrade(&backing));
            eprintln!("MISS! new {:?}", backing.id);
            backing
        };

        self.by_handle.insert(fh, Arc::clone(&backing));
        Ok((fh, backing))
    }

    /// The `Backing` behind an open file handle.
    fn get(&self, fh: u64) -> Option<Arc<Backing>> {
        self.by_handle.get(&fh).cloned()
    }

    /// Releases a file handle previously obtained from `get_or()`.  If this was a last user of a
    /// particular `BackingId` then it will be dropped.
    fn put(&mut self, fh: u64) {
        eprintln!("Put fh {fh}");
        match self.by_handle.remove(&fh) {
            None => eprintln!("ERROR: Put fh {fh} but it wasn't found in cache!!\n"),
            Some(backing) => eprintln!("Put fh {fh}, was {:?}\n", backing.id),
        }
    }
}

use std::sync::Arc;
use std::sync::Weak;

use parking_lot::Mutex;

use crate::common::args::CommonArgs;

#[derive(Debug)]
struct PassthroughFs {
    root_attr: FileAttr,
    passthrough_file_attr: FileAttr,
    backing_cache: Mutex<BackingCache>,
}

impl PassthroughFs {
    fn new() -> Self {
        let uid = nix::unistd::getuid().into();
        let gid = nix::unistd::getgid().into();

        let root_attr = FileAttr {
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
            uid,
            gid,
            rdev: 0,
            flags: 0,
            blksize: 512,
        };

        let passthrough_file_attr = FileAttr {
            ino: INodeNo(2),
            size: 123_456,
            blocks: 1,
            atime: UNIX_EPOCH, // 1970-01-01 00:00:00
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 333,
            gid: 333,
            rdev: 0,
            flags: 0,
            blksize: 512,
        };

        Self {
            root_attr,
            passthrough_file_attr,
            backing_cache: Mutex::new(BackingCache::default()),
        }
    }
}

impl Filesystem for PassthroughFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        // Passthrough is a Linux capability, which macFUSE does not have
        #[cfg(target_os = "macos")]
        {
            let _ = config;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "passthrough needs Linux",
            ))
        }
        #[cfg(not(target_os = "macos"))]
        {
            config
                .add_capabilities(InitFlags::FUSE_PASSTHROUGH)
                .unwrap();
            config.set_max_stack_depth(2).unwrap();
            Ok(())
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == INodeNo::ROOT && name.to_str() == Some("passthrough") {
            reply.entry(&TTL, &self.passthrough_file_attr, fuser::Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino.0 {
            1 => reply.attr(&TTL, &self.root_attr),
            2 => reply.attr(&TTL, &self.passthrough_file_attr),
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        _flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        if ino != INodeNo(2) {
            reply.error(Errno::ENOENT);
            return;
        }

        let (fh, backing) = self
            .backing_cache
            .lock()
            .get_or(ino, || {
                let file = File::open("/etc/profile")?;
                let id = reply.open_backing(&file)?;
                Ok(Backing { id, file })
            })
            .unwrap();

        eprintln!("  -> opened_passthrough({fh:?}, 0, {:?});\n", backing.id);
        reply.opened_passthrough(FileHandle(fh), FopenFlags::empty(), &backing.id);
    }

    /// The kernel reads most of a passthrough file from the backing file itself, but still sends
    /// some reads here, such as those that fill the page cache for `readahead(2)`
    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let Some(backing) = self.backing_cache.lock().get(fh.into()) else {
            reply.error(Errno::EBADF);
            return;
        };
        eprintln!("read() fallback: fh {fh:?}, offset {offset}, size {size}");
        let mut buf = vec![0; size as usize];
        match backing.file.read_at(&mut buf, offset) {
            Ok(n) => reply.data(&buf[..n]),
            Err(e) => reply.error(Errno::from(e)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.backing_cache.lock().put(_fh.into());
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "passthrough"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(INodeNo(entry.0), (i + 1) as u64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    let args = Args::parse();
    env_logger::init();

    let mut cfg = args.common_args.config();
    cfg.mount_options
        .extend([MountOption::FSName("passthrough".to_string())]);
    let fs = PassthroughFs::new();
    fuser::mount(fs, &args.common_args.mount_point, &cfg).unwrap();
}
