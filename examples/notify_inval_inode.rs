// Translated from libfuse's example/notify_{inval_inode,store_retrieve}.c:
//    Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>
//
// Translated to Rust/fuser by Zev Weiss <zev@bewilderbeest.net>
//
// Due to the above provenance, unlike the rest of fuser this file is
// licensed under the terms of the GNU GPLv2.

use std::{
    convert::TryInto,
    ffi::OsStr,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;

use fuser::{
    consts, Bytes, Dirent, DirentList, Entry, Errno,
    FileAttr, FileType, Filesystem, Forget, MountOption, Open, RequestMeta, FUSE_ROOT_ID,
};

struct ClockFS<'a> {
    file_contents: Arc<Mutex<String>>,
    lookup_cnt: &'a AtomicU64,
}

impl ClockFS<'_> {
    const FILE_INO: u64 = 2;
    const FILE_NAME: &'static str = "current_time";

    fn stat(&self, ino: u64) -> Option<FileAttr> {
        let (kind, perm, size) = match ino {
            FUSE_ROOT_ID => (FileType::Directory, 0o755, 0),
            Self::FILE_INO => (
                FileType::RegularFile,
                0o444,
                self.file_contents.lock().unwrap().len(),
            ),
            _ => return None,
        };
        let now = SystemTime::now();
        Some(FileAttr {
            ino,
            size: size.try_into().unwrap(),
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: 0,
        })
    }
}

impl Filesystem for ClockFS<'_> {
    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: &Path) -> Result<Entry, Errno> {
        if parent != FUSE_ROOT_ID || name != OsStr::new(Self::FILE_NAME) {
            return Err(Errno::ENOENT);
        }

        self.lookup_cnt.fetch_add(1, SeqCst);
        match self.stat(ClockFS::FILE_INO) {
            Some(attr) => Ok(Entry {
                ino: attr.ino,
                generation: None,
                file_ttl: Duration::MAX,
                attr,
                attr_ttl: Duration::MAX,
            }),
            None => Err(Errno::EIO), // Should not happen
        }
    }

    fn forget(&mut self, _req: RequestMeta, target: Forget) {
        if target.ino == ClockFS::FILE_INO {
            let prev = self.lookup_cnt.fetch_sub(target.nlookup, SeqCst);
            assert!(prev >= target.nlookup);
        } else {
            assert!(target.ino == FUSE_ROOT_ID);
        }
    }

    fn getattr(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: Option<u64>,
    ) -> Result<(FileAttr, Duration), Errno> {
        match self.stat(ino) {
            Some(attr) => Ok((attr, Duration::MAX)),
            None => Err(Errno::ENOENT),
        }
    }

    fn readdir<'dir, 'name>(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64,
        offset: i64,
        _max_bytes: u32,
    ) -> Result<DirentList<'dir, 'name>, Errno> {
        if ino != FUSE_ROOT_ID {
            return Err(Errno::ENOTDIR);
        }
        // In this example, construct and return an owned vector,
        // containing a reference to borrowed ('static) bytes.
        let mut entries: Vec<Dirent> = Vec::new();
        if offset == 0 {
            let entry_data = Dirent {
                ino: ClockFS::FILE_INO,
                offset: 1, // This entry's cookie
                kind: FileType::RegularFile,
                name: Bytes::Ref(Self::FILE_NAME.as_bytes()),
            };
            entries.push(entry_data);
        }
        // If offset is > 0, we've already returned the single entry during a previous request,
        // so just return the empty vector.
        Ok(entries.into())
    }

    fn open(&mut self, _req: RequestMeta, ino: u64, flags: i32) -> Result<Open, Errno> {
        if ino == FUSE_ROOT_ID {
            Err(Errno::EISDIR)
        } else if flags & libc::O_ACCMODE != libc::O_RDONLY {
            Err(Errno::EACCES)
        } else if ino != Self::FILE_INO {
            eprintln!("Got open for nonexistent inode {ino}");
            Err(Errno::ENOENT)
        } else {
            Ok(Open {
                fh: ino, // Using ino as fh, as it's unique for the file
                flags: consts::FOPEN_KEEP_CACHE,
            })
        }
    }

    fn read<'a>(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64, // fh is ino in this implementation as set in open()
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
    ) -> Result<Bytes<'a>, Errno> {
        assert!(ino == Self::FILE_INO);
        if offset < 0 {
            return Err(Errno::EINVAL);
        }
        let file_guard = self.file_contents.lock().unwrap();
        let filedata = file_guard.as_bytes();
        let dlen: i64 = filedata.len().try_into().map_err(|_| Errno::EIO)?; // EIO if size doesn't fit i64

        let start_index: usize = offset.try_into().map_err(|_| Errno::EINVAL)?;

        let data_to_return = if start_index > filedata.len() {
            Vec::new() // Read past EOF
        } else {
            let end_index: usize = (offset + i64::from(size))
                .min(dlen) // cap at file length
                .try_into()
                .map_err(|_| Errno::EINVAL)?; // Should not fail if dlen fits usize
            let stop_index = std::cmp::min(end_index, filedata.len());
            filedata[start_index..stop_index].to_vec()
        };

        eprintln!(
            "read returning {} bytes at offset {}",
            data_to_return.len(),
            offset
        );
        Ok(Bytes::from(data_to_return))
    }
}

fn now_string() -> String {
    let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        panic!("Pre-epoch SystemTime");
    };
    format!("The current time is {}\n", d.as_secs())
}

#[derive(Parser)]
struct Options {
    /// Mount demo filesystem at given path
    mount_point: String,

    /// Update interval for filesystem contents
    #[clap(short, long, default_value_t = 1.0)]
    update_interval: f32,

    /// Disable kernel notifications
    #[clap(short, long)]
    no_notify: bool,

    /// Use `notify_store()` instead of `notify_inval_inode()`
    #[clap(short = 's', long)]
    notify_store: bool,
}

fn main() {
    let opts = Options::parse();
    let options = vec![MountOption::RO, MountOption::FSName("clock".to_string())];
    let fdata = Arc::new(Mutex::new(now_string()));
    let lookup_cnt = Box::leak(Box::new(AtomicU64::new(0)));
    let fs = ClockFS {
        file_contents: fdata.clone(),
        lookup_cnt,
    };

    let session = fuser::Session::new(fs, opts.mount_point, &options).unwrap();
    let notifier = session.notifier();
    let _bg = session.spawn().unwrap();

    loop {
        let mut s = fdata.lock().unwrap();
        let olddata = std::mem::replace(&mut *s, now_string());
        drop(s);
        if !opts.no_notify && lookup_cnt.load(SeqCst) != 0 {
            if opts.notify_store {
                if let Err(e) =
                    notifier.store(ClockFS::FILE_INO, 0, fdata.lock().unwrap().as_bytes())
                {
                    eprintln!("Warning: failed to update kernel cache: {e}");
                }
            } else if let Err(e) =
                notifier.inval_inode(ClockFS::FILE_INO, 0, olddata.len().try_into().unwrap())
            {
                eprintln!("Warning: failed to invalidate inode: {e}");
            }
        }
        thread::sleep(Duration::from_secs_f32(opts.update_interval));
    }
}
