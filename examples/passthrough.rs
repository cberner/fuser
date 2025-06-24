// This example requires fuse 7.40 or later. Run with:
//
//   cargo run --example passthrough --features abi-7-40 /tmp/foobar

use clap::{crate_version, Arg, ArgAction, Command};
use fuser::{
    consts, BackingId, FileAttr, FileType, Filesystem, KernelConfig, MountOption, Attr, DirEntry,
    Entry, Open, Errno, RequestMeta,
};
use std::collections::HashMap;
use std::ffi::{OsString};
use std::fs::File;
use std::rc::{Rc, Weak};
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1); // 1 second

/// BackingCache is an example of how a filesystem might manage BackingId objects for fd
/// passthrough.  The idea is to avoid creating more than one BackingId object per file at a time.
///
/// We do this by keeping a weak "by inode" hash table mapping inode numbers to BackingId.  If a
/// BackingId already exists, we use it.  Otherwise, we create it.  This is not enough to keep the
/// BackingId alive, though.  For each Filesystem::open() request we allocate a fresh 'fh'
/// (monotonically increasing u64, next_fh, never recycled) and use that to keep a *strong*
/// reference on the BackingId for that open.  We drop it from the table on Filesystem::release(),
/// which means the BackingId will be dropped in the kernel when the last user of it closes.
///
/// In this way, if a request to open a file comes in and the file is already open, we'll reuse the
/// BackingId, but as soon as all references are closed, the BackingId will be dropped.
///
/// It's left as an exercise to the reader to implement an active cleanup of the by_inode table, if
/// desired, but our little example filesystem only contains one file. :)
#[derive(Debug, Default)]
struct BackingCache {
    by_handle: HashMap<u64, Rc<BackingId>>,
    by_inode: HashMap<u64, Weak<BackingId>>,
    next_fh: u64,
}

impl BackingCache {
    fn next_fh(&mut self) -> u64 {
        self.next_fh += 1;
        self.next_fh
    }

    /// Gets the existing BackingId for `ino` if it exists, or calls `callback` to create it.
    ///
    /// Returns a unique file handle and the BackingID (possibly shared, possibly new).  The
    /// returned file handle should be `put()` when you're done with it.
    fn get_or(
        &mut self,
        ino: u64,
        callback: impl Fn() -> std::io::Result<BackingId>,
    ) -> std::io::Result<(u64, Rc<BackingId>)> {
        let fh = self.next_fh();

        let id = if let Some(id) = self.by_inode.get(&ino).and_then(Weak::upgrade) {
            eprintln!("HIT! reusing {id:?}");
            id
        } else {
            let id = Rc::new(callback()?);
            self.by_inode.insert(ino, Rc::downgrade(&id));
            eprintln!("MISS! new {id:?}");
            id
        };

        self.by_handle.insert(fh, Rc::clone(&id));
        Ok((fh, id))
    }

    /// Releases a file handle previously obtained from `get_or()`.  If this was a last user of a
    /// particular BackingId then it will be dropped.
    fn put(&mut self, fh: u64) {
        eprintln!("Put fh {fh}");
        match self.by_handle.remove(&fh) {
            None => eprintln!("ERROR: Put fh {fh} but it wasn't found in cache!!\n"),
            Some(id) => eprintln!("Put fh {fh}, was {id:?}\n"),
        }
    }
}

#[derive(Debug)]
struct PassthroughFs {
    root_attr: FileAttr,
    passthrough_file_attr: FileAttr,
    backing_cache: BackingCache,
}

impl PassthroughFs {
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

        let passthrough_file_attr = FileAttr {
            ino: 2,
            size: 123456,
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
            backing_cache: Default::default(),
        }
    }
}

impl Filesystem for PassthroughFs {
    fn init(
        &mut self,
        _req: RequestMeta,
        config: KernelConfig,
    ) -> Result<KernelConfig, Errno> {
        let mut config = config;
        config.add_capabilities(consts::FUSE_PASSTHROUGH).unwrap();
        config.set_max_stack_depth(2).unwrap();
        Ok(config)
    }

    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: OsString) -> Result<Entry, Errno> {
        if parent == 1 && name.to_str() == Some("passthrough") {
            Ok(Entry {
                attr: self.passthrough_file_attr,
                ttl: TTL,
                generation: 0,
            })
        } else {
            Err(Errno::ENOENT)
        }
    }

    fn getattr(&mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: Option<u64>,
    ) -> Result<Attr, Errno> {
        match ino {
            1 => Ok(Attr{attr: self.root_attr, ttl: TTL}),
            2 => Ok(Attr{attr: self.passthrough_file_attr, ttl: TTL}),
            _ =>Err(Errno::ENOENT),
        }
    }

    fn open(&mut self, _req: RequestMeta, ino: u64, _flags: i32) -> Result<Open, Errno> {
        if ino != 2 {
            return Err(Errno::ENOENT);
        }

        let (fh, id) = self
            .backing_cache
            .get_or(ino, || {
                let _file = File::open("/etc/os-release")?;
                // TODO: Implement opening the backing file and returning appropriate
                // information, possibly including a BackingId within the Open struct,
                // or handle it through other means if fd-passthrough is intended here.
                Err(std::io::Error::new(std::io::ErrorKind::Other, "TODO: passthrough open not fully implemented"))
            })
            .unwrap();

        eprintln!("  -> opened_passthrough({fh:?}, 0, {id:?});\n");
        // TODO: Ensure fd-passthrough is correctly set up if intended.
        // The Open struct would carry necessary info.
        // TODO: implement flags for Open struct
        Ok(Open{fh, flags: 0 })
    }

    fn release(
        &mut self,
        _req: RequestMeta,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
    ) -> Result<(), Errno> {
        self.backing_cache.put(fh);
        Ok(())
    }

    fn readdir(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64,
        offset: i64,
        _max_bytes: u32
    ) -> Result<Vec<DirEntry>, Errno> {
        if ino != 1 {
            return Err(Errno::ENOENT);
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "passthrough"),
        ];
        let mut result=Vec::new();

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            result.push(DirEntry {
                ino: entry.0,
                offset: i as i64 + 1,
                kind: entry.1,
                name: OsString::from(entry.2),
            });
        }
        Ok(result)
    }
}

fn main() {
    let matches = Command::new("hello")
        .version(crate_version!())
        .author("Allison Karlitskaya")
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
    let mut options = vec![MountOption::FSName("passthrough".to_string())];
    if matches.get_flag("auto_unmount") {
        options.push(MountOption::AutoUnmount);
    }
    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    let fs = PassthroughFs::new();
    fuser::mount2(fs, mountpoint, &options).unwrap();
}
