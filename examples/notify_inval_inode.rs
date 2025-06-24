// Translated from libfuse's example/notify_{inval_inode,store_retrieve}.c:
//    Copyright (C) 2016 Nikolaus Rath <Nikolaus@rath.org>
//
// Translated to Rust/fuser by Zev Weiss <zev@bewilderbeest.net>
//
// Due to the above provenance, unlike the rest of fuser this file is
// licensed under the terms of the GNU GPLv2.

use std::{
    convert::TryInto,
    ffi::{OsStr, OsString},
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;

use fuser::{
    consts, Attr, DirEntry, Entry, Errno, FileAttr, FileType, Filesystem, Forget, MountOption, Open, RequestMeta, FUSE_ROOT_ID
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
    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: OsString) -> Result<Entry, Errno> {
        if parent != FUSE_ROOT_ID || name != OsStr::new(Self::FILE_NAME) {
            return Err(Errno::ENOENT);
        }

        self.lookup_cnt.fetch_add(1, SeqCst);
        match self.stat(ClockFS::FILE_INO) {
            Some(attr) => Ok(Entry {
                    attr,
                    ttl: Duration::MAX, // Effectively infinite TTL
                    generation: 0,
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

    fn getattr(&mut self, _req: RequestMeta, ino: u64, _fh: Option<u64>) -> Result<Attr, Errno> {
        match self.stat(ino) {
            Some(attr) => Ok(Attr {
                attr,
                ttl: Duration::MAX, // Effectively infinite TTL
            }),
            None => Err(Errno::ENOENT),
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
        if ino != FUSE_ROOT_ID {
            return Err(Errno::ENOTDIR);
        }
        let mut entries = Vec::new();
        if offset == 0 {
            entries.push(DirEntry {
                ino: ClockFS::FILE_INO,
                offset: 1, // Next offset
                kind: FileType::RegularFile,
                name: OsString::from(Self::FILE_NAME),
            });
        }
        // If offset is > 0, we've already returned the single entry, so return an empty vector.
        Ok(entries)
    }

    fn open(&mut self, _req: RequestMeta, ino: u64, flags: i32) -> Result<Open, Errno> {
        if ino == FUSE_ROOT_ID {
            Err(Errno::EISDIR)
        } else if flags & libc::O_ACCMODE != libc::O_RDONLY {
            Err(Errno::EACCES)
        } else if ino != Self::FILE_INO {
            eprintln!("Got open for nonexistent inode {}", ino);
            Err(Errno::ENOENT)
        } else {
            Ok(Open {
                fh: ino, // Using ino as fh, as it's unique for the file
                flags: consts::FOPEN_KEEP_CACHE,
            })
        }
    }

    fn read(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64, // fh is ino in this implementation as set in open()
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
    ) -> Result<Vec<u8>, Errno> {
        assert!(ino == Self::FILE_INO);
        if offset < 0 {
            return Err(Errno::EINVAL);
        }
        let file = self.file_contents.lock().unwrap();
        let filedata = file.as_bytes();
        let dlen: i64 = filedata.len().try_into().map_err(|_| Errno::EIO)?; // EIO if size doesn't fit i64

        let start_offset: usize = offset.try_into().map_err(|_| Errno::EINVAL)?;
        if start_offset > filedata.len() {
             return Ok(Vec::new()); // Read past EOF
        }

        let end_offset: usize = (offset + i64::from(size))
            .min(dlen) // cap at file length
            .try_into()
            .map_err(|_| Errno::EINVAL)?; // Should not fail if dlen fits usize

        let actual_end = std::cmp::min(end_offset, filedata.len());

        eprintln!(
            "read returning {} bytes at offset {}",
            actual_end.saturating_sub(start_offset),
            offset
        );
        Ok(filedata[start_offset..actual_end].to_vec())
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

    /// Use notify_store() instead of notify_inval_inode()
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
                    eprintln!("Warning: failed to update kernel cache: {}", e);
                }
            } else if let Err(e) =
                notifier.inval_inode(ClockFS::FILE_INO, 0, olddata.len().try_into().unwrap())
            {
                eprintln!("Warning: failed to invalidate inode: {}", e);
            }
        }
        thread::sleep(Duration::from_secs_f32(opts.update_interval));
    }
}
