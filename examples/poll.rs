// Translated from libfuse's example/poll.c:
//    Copyright (C) 2008       SUSE Linux Products GmbH
//    Copyright (C) 2008       Tejun Heo <teheo@suse.de>
//
// Translated to Rust/fuser by Zev Weiss <zev@bewilderbeest.net>
//
// Due to the above provenance, unlike the rest of fuser this file is
// licensed under the terms of the GNU GPLv2.

// Requires feature = "abi-7-11"

use std::{
    convert::TryInto,
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt}, // for converting to and from
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Arc, Mutex,
    },
    thread,
    time::{Duration, UNIX_EPOCH},
};

use fuser::{
    consts::{FOPEN_DIRECT_IO, FOPEN_NONSEEKABLE, FUSE_POLL_SCHEDULE_NOTIFY},
    FileAttr, FileType, MountOption, RequestMeta, Entry, Attr, DirEntry, Open, Errno, FUSE_ROOT_ID,
};

const NUMFILES: u8 = 16;
const MAXBYTES: u64 = 10;

struct FSelData {
    bytecnt: [u64; NUMFILES as usize],
    open_mask: u16,
    notify_mask: u16,
    poll_handles: [u64; NUMFILES as usize],
}

struct FSelFS {
    data: Arc<Mutex<FSelData>>,
}

impl FSelData {
    fn idx_to_ino(idx: u8) -> u64 {
        let idx: u64 = idx.into();
        FUSE_ROOT_ID + idx + 1
    }

    fn ino_to_idx(ino: u64) -> u8 {
        (ino - (FUSE_ROOT_ID + 1))
            .try_into()
            .expect("out-of-range inode number")
    }

    fn filestat(&self, idx: u8) -> FileAttr {
        assert!(idx < NUMFILES);
        FileAttr {
            ino: Self::idx_to_ino(idx),
            size: self.bytecnt[idx as usize],
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: 0,
        }
    }
}

impl FSelFS {
    fn get_data(&self) -> std::sync::MutexGuard<'_, FSelData> {
        self.data.lock().unwrap()
    }
}

impl fuser::Filesystem for FSelFS {
    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: OsString) -> Result<Entry, Errno> {
        if parent != FUSE_ROOT_ID || name.len() != 1 {
            return Err(Errno::ENOENT);
        }

        let name_bytes = name.as_bytes();

        let idx = match name_bytes[0] {
            b'0'..=b'9' => name_bytes[0] - b'0',
            b'A'..=b'F' => name_bytes[0] - b'A' + 10,
            _ => {
                return Err(Errno::ENOENT);
            }
        };

        Ok(Entry {
            attr: self.get_data().filestat(idx),
            ttl: Duration::ZERO,
            generation: 0,
        })
    }

    fn getattr(&mut self, _req: RequestMeta, ino: u64, _fh: Option<u64>) -> Result<Attr, Errno> {
        if ino == FUSE_ROOT_ID {
            let a = FileAttr {
                ino: FUSE_ROOT_ID,
                size: 0,
                blocks: 0,
                atime: UNIX_EPOCH,
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
                kind: FileType::Directory,
                perm: 0o555,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0,
                blksize: 0,
            };
            return Ok(Attr { ttl: Duration::ZERO, attr: a });
        }
        let idx = FSelData::ino_to_idx(ino);
        if idx < NUMFILES {
            Ok(Attr {
                attr: self.get_data().filestat(idx),
                ttl: Duration::ZERO,
            })
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
        if ino != FUSE_ROOT_ID {
            return Err(Errno::ENOTDIR);
        }

        let Ok(start_offset): Result<u8, _> = offset.try_into() else {
            return Err(Errno::EINVAL);
        };

        let mut entries = Vec::new();
        for idx in start_offset..NUMFILES {
            let ascii_char_val = match idx {
                0..=9 => b'0' + idx,
                10..=15 => b'A' + idx - 10, // Corrected range to 15 for NUMFILES = 16
                _ => panic!("idx out of range for NUMFILES"),
            };
            let name_bytes = vec![ascii_char_val]; // Byte vector (but just one byte)
            let name = OsString::from_vec(name_bytes);
            entries.push(DirEntry {
                ino: FSelData::idx_to_ino(idx),
                offset: (idx + 1).into(),
                kind: FileType::RegularFile,
                name,
            });
            // TODO: compare to _max_bytes; stop if full.
        }
        Ok(entries)
    }

    fn open(&mut self, _req: RequestMeta, ino: u64, flags: i32) -> Result<Open, Errno> {
        let idx = FSelData::ino_to_idx(ino);
        if idx >= NUMFILES {
            return Err(Errno::ENOENT);
        }

        if (flags & libc::O_ACCMODE) != libc::O_RDONLY {
            return Err(Errno::EACCES);
        }

        {
            let mut d = self.get_data();

            if d.open_mask & (1 << idx) != 0 {
                return Err(Errno::EBUSY);
            }
            d.open_mask |= 1 << idx;
        }

        Ok(Open {
            fh: idx.into(), // Using idx as file handle
            flags: FOPEN_DIRECT_IO | FOPEN_NONSEEKABLE,
        })
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
        let idx = fh; // fh is the idx from open()
        if idx >= NUMFILES.into() {
            return Err(Errno::EBADF);
        }
        self.get_data().open_mask &= !(1 << idx);
        Ok(())
    }

    fn read(
        &mut self,
        _req: RequestMeta,
        _ino: u64,
        fh: u64,
        _offset: i64, // offset is ignored due to FOPEN_NONSEEKABLE
        max_size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
    ) -> Result<Vec<u8>, Errno> {
        let Ok(idx): Result<u8, _> = fh.try_into() else {
            return Err(Errno::EINVAL);
        };
        if idx >= NUMFILES {
            return Err(Errno::EBADF);
        }
        let cnt = &mut self.get_data().bytecnt[idx as usize];
        let size = (*cnt).min(max_size.into());
        println!("READ   {:X} transferred={} cnt={}", idx, size, *cnt);
        *cnt -= size;
        let elt = match idx {
            0..=9 => b'0' + idx,
            10..=15 => b'A' + idx - 10, // Corrected range
            _ => panic!("idx out of range for NUMFILES"),
        };
        let data = vec![elt; size.try_into().unwrap()];
        Ok(data)
    }

    #[cfg(feature = "abi-7-11")]
    fn poll(
        &mut self,
        _req: RequestMeta,
        _ino: u64,
        fh: u64,
        ph: u64,
        _events: u32,
        flags: u32,
    ) -> Result<u32, Errno> {
        static POLLED_ZERO: AtomicU64 = AtomicU64::new(0);
        let Ok(idx): Result<u8, _> = fh.try_into() else {
            return Err(Errno::EINVAL);
        };
        if idx >= NUMFILES {
            return Err(Errno::EBADF);
        }

        let revents = {
            let mut d = self.get_data();

            if flags & FUSE_POLL_SCHEDULE_NOTIFY != 0 {
                d.notify_mask |= 1 << idx;
                d.poll_handles[idx as usize] = ph;
            }

            let nbytes = d.bytecnt[idx as usize];
            if nbytes != 0 {
                println!(
                    "POLL   {:X} cnt={} polled_zero={}",
                    idx,
                    nbytes,
                    POLLED_ZERO.swap(0, SeqCst)
                );
                libc::POLLIN.try_into().unwrap()
            } else {
                POLLED_ZERO.fetch_add(1, SeqCst);
                0
            }
        };
        Ok(revents)
    }
}

fn producer(data: &Mutex<FSelData>, notifier: &fuser::Notifier) {
    let mut idx: u8 = 0;
    let mut nr = 1;
    loop {
        {
            let mut d = data.lock().unwrap();
            let mut t = idx;

            for _ in 0..nr {
                let tidx = t as usize;
                if d.bytecnt[tidx] != MAXBYTES {
                    d.bytecnt[tidx] += 1;
                    if d.notify_mask & (1 << t) != 0 {
                        println!("NOTIFY {:X}", t);
                        if let Err(e) = notifier.poll(d.poll_handles[tidx]) {
                            eprintln!("poll notification failed: {}", e);
                        }
                        d.notify_mask &= !(1 << t);
                    }
                }

                t = (t + NUMFILES / nr) % NUMFILES;
            }

            idx = (idx + 1) % NUMFILES;
            if idx == 0 {
                nr = (nr * 2) % 7;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn main() {
    let options = vec![MountOption::RO, MountOption::FSName("fsel".to_string())];
    let data = Arc::new(Mutex::new(FSelData {
        bytecnt: [0; NUMFILES as usize],
        open_mask: 0,
        notify_mask: 0,
        poll_handles: [0; NUMFILES as usize],
    }));
    let fs = FSelFS { data: data.clone() };

    let mntpt = std::env::args().nth(1).unwrap();
    let session = fuser::Session::new(fs, mntpt, &options).unwrap();
    let bg = session.spawn().unwrap();

    producer(&data, &bg.notifier());
}

#[cfg(test)]
mod test {
    use super::*;
    use fuser::{Filesystem, RequestMeta, Errno};
    use std::sync::{Arc, Mutex};

    fn setup_test_fs() -> FSelFS {
        let data = Arc::new(Mutex::new(FSelData {
            bytecnt: [0; NUMFILES as usize],
            open_mask: 0,
            notify_mask: 0,
            poll_handles: [0; NUMFILES as usize],
        }));
        FSelFS { data }
    }

    #[test]
    fn test_poll_data_available() {
        let mut fs = setup_test_fs();
        let req = RequestMeta { unique: 0, uid: 0, gid: 0, pid: 0 };
        let idx = 0;
        let fh = idx as u64;
        let ph = 1;
        {
            let mut data = fs.get_data();
            data.bytecnt[idx as usize] = 5; // Simulate data available
        }
        let result = fs.poll(req, FSelData::idx_to_ino(idx), fh, ph, libc::POLLIN as u32, FUSE_POLL_SCHEDULE_NOTIFY);
        assert!(result.is_ok(), "Poll should succeed when data is available");
        if let Ok(revents) = result {
            assert_eq!(revents, libc::POLLIN as u32, "Should return POLLIN when data is available");
        }
        let data = fs.get_data();
        assert_eq!(data.notify_mask & (1 << idx), 1 << idx, "Notify mask should be set for this index");
        assert_eq!(data.poll_handles[idx as usize], 1, "Poll handle should be stored");
    }

    #[test]
    fn test_poll_no_data() {
        let mut fs = setup_test_fs();
        let req = RequestMeta { unique: 0, uid: 0, gid: 0, pid: 0 };
        let idx = 0;
        let fh = idx as u64;
        let ph = 1;
        {
            let mut data = fs.get_data();
            data.bytecnt[idx as usize] = 0; // No data available
        }
        let result = fs.poll(req, FSelData::idx_to_ino(idx), fh, ph, libc::POLLIN as u32, FUSE_POLL_SCHEDULE_NOTIFY);
        assert!(result.is_ok(), "Poll should succeed even when no data is available");
        if let Ok(revents) = result {
            assert_eq!(revents, 0, "Should return 0 when no data is available");
        }
    }

    #[test]
    fn test_poll_invalid_handle() {
        let mut fs = setup_test_fs();
        let req = RequestMeta { unique: 0, uid: 0, gid: 0, pid: 0 };
        let invalid_idx = NUMFILES as u64;
        let ph = 1;
        let result = fs.poll(req, FSelData::idx_to_ino(0), invalid_idx, ph, libc::POLLIN as u32, FUSE_POLL_SCHEDULE_NOTIFY);
        assert!(result.is_err(), "Poll should fail for invalid file handle");
        if let Err(e) = result {
            assert_eq!(e, Errno::EBADF, "Should return EBADF for invalid handle");
        }
    }
}
