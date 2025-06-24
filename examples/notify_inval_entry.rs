// Translated from libfuse's example/notify_inval_entry.c:
//    Copyright (C) 2008       SUSE Linux Products GmbH
//    Copyright (C) 2008       Tejun Heo <teheo@suse.de>
//
// Translated to Rust/fuser by Zev Weiss <zev@bewilderbeest.net>
//
// Due to the above provenance, unlike the rest of fuser this file is
// licensed under the terms of the GNU GPLv2.

use std::{
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
    Attr, DirEntry, Entry, Errno, FileAttr, FileType, Filesystem, Forget, MountOption, RequestMeta, FUSE_ROOT_ID
};

struct ClockFS<'a> {
    file_name: Arc<Mutex<String>>,
    lookup_cnt: &'a AtomicU64,
    timeout: Duration,
}

impl ClockFS<'_> {
    const FILE_INO: u64 = 2;

    fn get_filename(&self) -> String {
        let n = self.file_name.lock().unwrap();
        n.clone()
    }

    fn stat(ino: u64) -> Option<FileAttr> {
        let (kind, perm) = match ino {
            FUSE_ROOT_ID => (FileType::Directory, 0o755),
            Self::FILE_INO => (FileType::RegularFile, 0o000),
            _ => return None,
        };
        let now = SystemTime::now();
        Some(FileAttr {
            ino,
            size: 0,
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
        if parent != FUSE_ROOT_ID || name != OsStr::new(&self.get_filename()) {
            return Err(Errno::ENOENT);
        }

        self.lookup_cnt.fetch_add(1, SeqCst);
        match ClockFS::stat(ClockFS::FILE_INO) {
            Some(attr) => Ok(Entry {
                attr,
                ttl: self.timeout,
                generation: 0,
            }),
            None => Err(Errno::EIO), // Should not happen if FILE_INO is valid
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
        match ClockFS::stat(ino) {
            Some(attr) => Ok(Attr {
                    attr,
                    ttl: self.timeout,
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
                offset: 1, // Next offset is 1
                kind: FileType::RegularFile,
                name: OsString::from(self.get_filename()),
            });
        }
        // If offset is > 0, we've already returned the single entry, so return an empty vector.
        Ok(entries)
    }
}

fn now_filename() -> String {
    let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        panic!("Pre-epoch SystemTime");
    };
    format!("Time_is_{}", d.as_secs())
}

#[derive(Parser)]
struct Options {
    /// Mount demo filesystem at given path
    mount_point: String,

    /// Timeout for kernel caches
    #[clap(short, long, default_value_t = 5.0)]
    timeout: f32,

    /// Update interval for filesystem contents
    #[clap(short, long, default_value_t = 1.0)]
    update_interval: f32,

    /// Disable kernel notifications
    #[clap(short, long)]
    no_notify: bool,

    /// Expire entries instead of invalidating them
    #[clap(short, long)]
    only_expire: bool,
}

fn main() {
    let opts = Options::parse();
    let options = vec![MountOption::RO, MountOption::FSName("clock".to_string())];
    let fname = Arc::new(Mutex::new(now_filename()));
    let lookup_cnt = Box::leak(Box::new(AtomicU64::new(0)));
    let fs = ClockFS {
        file_name: fname.clone(),
        lookup_cnt,
        timeout: Duration::from_secs_f32(opts.timeout),
    };

    let session = fuser::Session::new(fs, opts.mount_point, &options).unwrap();
    let notifier = session.notifier();
    let _bg = session.spawn().unwrap();

    loop {
        let mut fname = fname.lock().unwrap();
        let oldname = std::mem::replace(&mut *fname, now_filename());
        drop(fname);
        if !opts.no_notify && lookup_cnt.load(SeqCst) != 0 {
            if opts.only_expire {
                // fuser::notify_expire_entry(_SOME_HANDLE_, FUSE_ROOT_ID, &oldname);
            } else if let Err(e) = notifier.inval_entry(FUSE_ROOT_ID, oldname.as_ref()) {
                eprintln!("Warning: failed to invalidate entry '{}': {}", oldname, e);
            }
        }
        thread::sleep(Duration::from_secs_f32(opts.update_interval));
    }
}
