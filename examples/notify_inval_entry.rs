// Translated from libfuse's example/notify_inval_entry.c:
//    Copyright (C) 2008       SUSE Linux Products GmbH
//    Copyright (C) 2008       Tejun Heo <teheo@suse.de>
//
// Translated to Rust/fuser by Zev Weiss <zev@bewilderbeest.net>
//
// Due to the above provenance, unlike the rest of fuser this file is
// licensed under the terms of the GNU GPLv2.
//
// Converted to the synchronous execution model by Richard Lawrence

use std::{
    ffi::OsString,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[allow(unused_imports)]
use log::{error, warn, info, debug};
use clap::Parser;
use crossbeam_channel::{Receiver, Sender};
use fuser::{
    Dirent, DirentList, Entry, Errno, FileAttr, FileType, Filesystem, Forget,
    FsStatus, InvalEntry, MountOption, Notification, RequestMeta, FUSE_ROOT_ID,
};
struct ClockFS {
    file_name: OsString,
    lookup_cnt: u64,
    last_update: SystemTime,
    opts: Options,
    timeout: Duration,
    update_interval: Duration,
    notification_sender: Option<Sender<Notification>>,
    // the reply is just for some extra logging
    notification_reply: Option<Receiver<std::io::Result<()>>>,
}

impl ClockFS {
    const FILE_INO: u64 = 2;

    fn get_filename(&self) -> OsString {
        self.file_name.clone()
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

impl Filesystem for ClockFS {
    #[cfg(feature = "abi-7-11")]
    fn init_notification_sender(
        &mut self,
        sender: Sender<Notification>,
    ) -> bool {
        self.notification_sender = Some(sender);
        true
    }

    fn heartbeat(&mut self) -> Result<FsStatus, Errno> {
        // log the reply, if there is one.
        if let Some(r) = &self.notification_reply {
            if let Ok(result) = r.try_recv() {
                match result {
                    Ok(()) => debug!("Received OK reply"),
                    Err(e) => warn!("Received error reply: {e}"),
                }
                // Only read a reply once.
                self.notification_reply=None;
            }
        }
        let now = SystemTime::now();
        if now.duration_since(self.last_update).unwrap_or_default() >= self.update_interval {
            // Update filename
            let old_filename = self.get_filename();
            self.file_name = now_filename();
            self.last_update = now;
            // Notifications, as appropriate
            if !self.opts.no_notify && self.lookup_cnt != 0 {
                if let Some(sender) = &self.notification_sender {
                    if self.opts.only_expire {
                        // TODO: implement expiration method
                    } else {
                        // invalidate old_filename
                        let notification = Notification::from(InvalEntry {
                            parent: FUSE_ROOT_ID,
                            name: old_filename,
                        });
                        if let Err(e) = sender.send(notification) {
                            warn!("Warning: failed to send InvalEntry notification: {e}");
                        } else {
                            info!("Sent InvalEntry notification (old filename).");
                        }
                        // invalidate new filename
                        let (s, r) = crossbeam_channel::bounded(1);
                        let notification = Notification::InvalEntry((
                            InvalEntry {
                                parent: FUSE_ROOT_ID,
                                name: self.get_filename(),
                            },
                            Some(s),
                        ));
                        if let Err(e) = sender.send(notification) {
                            warn!("Warning: failed to send InvalEntry notification: {e}");
                        } else {
                            info!("Sent InvalEntry notification (new filename).");
                            self.notification_reply = Some(r);
                        }
                    }
                }
            }
        }
        Ok(FsStatus::Ready)
    }

    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: &Path) -> Result<Entry, Errno> {
        if parent != FUSE_ROOT_ID || name != self.file_name {
            return Err(Errno::ENOENT);
        }
        self.lookup_cnt += 1;
        match ClockFS::stat(ClockFS::FILE_INO) {
            Some(attr) => Ok(Entry {
                ino: attr.ino,
                generation: None,
                file_ttl: self.timeout,
                attr,
                attr_ttl: self.timeout,
            }),
            None => Err(Errno::EIO), // Should not happen if FILE_INO is valid
        }
    }

    fn forget(&mut self, _req: RequestMeta, target: Forget) {
        if target.ino == ClockFS::FILE_INO {
            assert!(self.lookup_cnt >= target.nlookup);
            self.lookup_cnt -= target.nlookup;
        } else {
            assert!(target.ino == FUSE_ROOT_ID);
        }
    }

    fn getattr(&mut self, _req: RequestMeta, ino: u64, _fh: Option<u64>) -> Result<(FileAttr, Duration), Errno> {
        match ClockFS::stat(ino) {
            Some(attr) => Ok((attr, self.timeout)),
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
        // containing owned bytes.
        let mut entries= Vec::new();
        if offset == 0 {
            let entry = Dirent {
                ino: ClockFS::FILE_INO,
                offset: 1,
                kind: FileType::RegularFile,
                name: self.get_filename().into(),
            };
            entries.push(entry);
        }
        // If offset is > 0, we've already returned the single entry during a previous request,
        // so just return the empty vector.
        Ok(entries.into())
    }
}

fn now_filename() -> OsString {
    let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        panic!("Pre-epoch SystemTime");
    };
    OsString::from(format!("Time_is_{}", d.as_secs()))
}

#[derive(Parser, Debug)]
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
    env_logger::init();
    let opts = Options::parse();
    eprintln!("Mounting ClockFS (entry invalidation) at {}", &opts.mount_point);
    eprintln!("Press Ctrl-C to unmount and exit.");

    let mount_point = OsString::from(&opts.mount_point);
    let timeout = Duration::from_secs_f32(opts.timeout);
    let update_interval = Duration::from_secs_f32(opts.update_interval);
    let fs = ClockFS {
        file_name: now_filename(),
        lookup_cnt: 0,
        last_update: SystemTime::now(),
        opts,
        timeout,
        update_interval,
        notification_sender: None,
        notification_reply: None,
    };
    let mount_options = vec![MountOption::RO, MountOption::FSName("clock_entry".to_string())];
    let mut session = fuser::Session::new(fs, &mount_point, &mount_options)
        .unwrap_or_else(|e| panic!("Failed to create FUSE session: {e}"));

    session
        .run_with_notifications()
        .expect("Session ended with an error."); //TODO: log the error

    eprintln!("ClockFS (entry invalidation) unmounted and exited.");
}
