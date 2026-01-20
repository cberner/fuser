// Translated from libfuse's example/poll.c:
//    Copyright (C) 2008       SUSE Linux Products GmbH
//    Copyright (C) 2008       Tejun Heo <teheo@suse.de>
//
// Translated to Rust/fuser by Zev Weiss <zev@bewilderbeest.net>
//
// Due to the above provenance, unlike the rest of fuser this file is
// licensed under the terms of the GNU GPLv2.

use std::convert::TryInto;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::SeqCst;
use std::thread;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::FopenFlags;
use fuser::INodeNo;
use fuser::LockOwner;
use fuser::MountOption;
use fuser::OpenAccMode;
use fuser::OpenFlags;
use fuser::PollEvents;
use fuser::PollFlags;
use fuser::PollHandle;
use fuser::ReadFlags;
use fuser::ReplyAttr;
use fuser::ReplyData;
use fuser::ReplyDirectory;
use fuser::ReplyEmpty;
use fuser::ReplyEntry;
use fuser::ReplyOpen;
use fuser::Request;

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
    fn idx_to_ino(idx: u8) -> INodeNo {
        let idx: u64 = idx.into();
        INodeNo(INodeNo::ROOT.0 + idx + 1)
    }

    fn ino_to_idx(ino: INodeNo) -> u8 {
        (ino.0 - (INodeNo::ROOT.0 + 1))
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
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent != INodeNo::ROOT || name.len() != 1 {
            reply.error(Errno::ENOENT);
            return;
        }

        let name = name.as_bytes();

        let idx = match name[0] {
            b'0'..=b'9' => name[0] - b'0',
            b'A'..=b'F' => name[0] - b'A' + 10,
            _ => {
                reply.error(Errno::ENOENT);
                return;
            }
        };

        reply.entry(
            &Duration::ZERO,
            &self.get_data().filestat(idx),
            fuser::Generation(0),
        );
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino == INodeNo::ROOT {
            let a = FileAttr {
                ino: INodeNo::ROOT,
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
            reply.attr(&Duration::ZERO, &a);
            return;
        }
        let idx = FSelData::ino_to_idx(ino);
        if idx < NUMFILES {
            reply.attr(&Duration::ZERO, &self.get_data().filestat(idx));
        } else {
            reply.error(Errno::ENOENT);
        }
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
            reply.error(Errno::ENOTDIR);
            return;
        }

        let Ok(offset): Result<u8, _> = offset.try_into() else {
            reply.error(Errno::EINVAL);
            return;
        };

        for idx in offset..NUMFILES {
            let ascii = match idx {
                0..=9 => [b'0' + idx],
                10..=16 => [b'A' + idx - 10],
                _ => panic!(),
            };
            let name = OsStr::from_bytes(&ascii);
            if reply.add(
                FSelData::idx_to_ino(idx),
                (idx + 1).into(),
                FileType::RegularFile,
                name,
            ) {
                break;
            }
        }

        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let idx = FSelData::ino_to_idx(ino);
        if idx >= NUMFILES {
            reply.error(Errno::ENOENT);
            return;
        }

        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            reply.error(Errno::EACCES);
            return;
        }

        {
            let mut d = self.get_data();

            if d.open_mask & (1 << idx) != 0 {
                reply.error(Errno::EBUSY);
                return;
            }

            d.open_mask |= 1 << idx;
        }

        reply.opened(
            FileHandle(idx.into()),
            FopenFlags::FOPEN_DIRECT_IO | FopenFlags::FOPEN_NONSEEKABLE,
        );
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: i32,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let idx: u64 = _fh.into();
        if idx >= NUMFILES.into() {
            reply.error(Errno::EBADF);
            return;
        }
        self.get_data().open_mask &= !(1 << idx);
        reply.ok();
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _offset: u64,
        size: u32,
        _flags: ReadFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let fh: u64 = fh.into();
        let Ok(idx): Result<u8, _> = fh.try_into() else {
            reply.error(Errno::EINVAL);
            return;
        };
        if idx >= NUMFILES {
            reply.error(Errno::EBADF);
            return;
        }
        let cnt = &mut self.get_data().bytecnt[idx as usize];
        let size = (*cnt).min(size.into());
        println!("READ   {:X} transferred={} cnt={}", idx, size, *cnt);
        *cnt -= size;
        let elt = match idx {
            0..=9 => b'0' + idx,
            10..=16 => b'A' + idx - 10,
            _ => panic!(),
        };
        let data = vec![elt; size.try_into().unwrap()];
        reply.data(data.as_slice());
    }

    fn poll(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        ph: PollHandle,
        _events: PollEvents,
        flags: PollFlags,
        reply: fuser::ReplyPoll,
    ) {
        static POLLED_ZERO: AtomicU64 = AtomicU64::new(0);
        let fh: u64 = fh.into();
        let Ok(idx): Result<u8, _> = fh.try_into() else {
            reply.error(Errno::EINVAL);
            return;
        };
        if idx >= NUMFILES {
            reply.error(Errno::EBADF);
            return;
        }

        let revents = {
            let mut d = self.get_data();

            if flags.contains(PollFlags::FUSE_POLL_SCHEDULE_NOTIFY) {
                d.notify_mask |= 1 << idx;
                d.poll_handles[idx as usize] = ph.into();
            }

            let nbytes = d.bytecnt[idx as usize];
            if nbytes != 0 {
                println!(
                    "POLL   {:X} cnt={} polled_zero={}",
                    idx,
                    nbytes,
                    POLLED_ZERO.swap(0, SeqCst)
                );
                PollEvents::POLLIN
            } else {
                POLLED_ZERO.fetch_add(1, SeqCst);
                PollEvents::empty()
            }
        };

        reply.poll(revents);
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
                        println!("NOTIFY {t:X}");
                        if let Err(e) = notifier.poll(d.poll_handles[tidx]) {
                            eprintln!("poll notification failed: {e}");
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
