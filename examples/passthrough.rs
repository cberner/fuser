// This example requires fuse 7.40 or later.
//
// To run this example, do the following:
//
//     sudo RUST_LOG=info ./target/debug/examples/passthrough /tmp/mnt &
//     sudo cat /tmp/mnt/passthrough
//     sudo pkill passthrough
//     sudo umount /tmp/mnt

use clap::{crate_version, Arg, ArgAction, Command};
use crossbeam_channel::{Sender, Receiver};
use fuser::{
    consts, Bytes, Dirent, DirentList, Entry, Errno, FileAttr, FileType,
    Filesystem, KernelConfig, MountOption, Open, Notification, RequestMeta,
};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::fs::File;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1); // 1 second
const BACKING_TIMEOUT: Duration = Duration::from_secs(2); // 2 seconds

// ----- BackingID -----

// A BackingId can be in three states: pending, ready, and closed.
// The closed variant is not strictly necessary; it simply provides some additional logging.
#[derive(Debug)]
enum BackingStatus {
    Pending(PendingBackingId),
    Ready(ReadyBackingId),
    // Closed variant is just for the extra logging
    Closed(ClosedBackingId),
}

#[derive(Debug)]
struct PendingBackingId {
    // reply will receive a backing_id from the kernel
    reply: Receiver<io::Result<u32>>,
    #[allow(dead_code)]
    // The file needs to stay open until the kernel finishes processing the open backing request.
    // It's behind an Arc so that if the Filesystem plans to interact with the file again later,
    // the Filesystem can clone the Arc to avoid a redundant File::open() operation.
    _file: Arc<File>,
}

#[derive(Debug)]
struct ReadyBackingId {
    // The notifier is used to safely close the backing id after any miscellaneous unexpected failures.
    notifier: Sender<Notification>,
    // This is the literal backing_id the kernel assigns to the filesystem.
    backing_id: u32,
    // there is a limit to how many you backing id the filesystem can hold open.
    // timestamp is one example strategy for retiring old backing ids.
    timestamp: SystemTime,
    // The reply_sender is just for extra logging.
    reply_sender: Option<Sender<io::Result<u32>>>,
}

impl Drop for ReadyBackingId {
    fn drop(&mut self) {
        // It is important to notify the kernel when backing ids are no longer in use.
        let notification = Notification::CloseBacking((self.backing_id, self.reply_sender.take()));
        let _ = self.notifier.send(notification);
        // TODO: handle the case where the notifier is broken.
    }
}

#[derive(Debug)]
struct ClosedBackingId {
    // the reply is just for extra logging
    reply: Receiver<io::Result<u32>>,
}

#[derive(Debug)]
struct PassthroughFs {
    root_attr: FileAttr,
    passthrough_file_attr: FileAttr,
    backing_cache: HashMap<u64, BackingStatus>,
    next_fh: u64,
    notification_sender: Option<Sender<Notification>>,
}

const ROOT_DIR_ENTRIES: [Dirent; 3] = [
    Dirent { ino: 1, offset: 1, kind: FileType::Directory,   name: Bytes::Ref(b".") },
    Dirent { ino: 1, offset: 2, kind: FileType::Directory,   name: Bytes::Ref(b"..") },
    Dirent { ino: 2, offset: 3, kind: FileType::RegularFile, name: Bytes::Ref(b"passthrough") },
];

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
            backing_cache: HashMap::new(),
            next_fh: 0,
            notification_sender: None,
        }
    }

    fn next_fh(&mut self) -> u64 {
        self.next_fh += 1;
        self.next_fh
    }

    // Get the backing status for a given inode, after all available updates are applied.
    // This will advance the status as appropriate and remove it from the cache if it is stale.
    // The returning an immutable reference to the updated status (or None)
    fn get_update_backing_status(&mut self, ino: u64) -> Option<&BackingStatus> {
        let mut remove = false;
        // using the "update, save a boolean, remove" pattern because we can't remove it while holding it as a mutable borrow.
        if let Some(backing_status) = self.backing_cache.get_mut(&ino) {
            if let Some(notifier) = self.notification_sender.clone() {
                if !Self::update_backing_status(backing_status, &notifier, true) {
                    remove = true;
                }
            }
        }
        if remove {
            self.backing_cache.remove(&ino);
        }
        self.backing_cache.get(&ino)
    }

    // update_backing_status mutates a BackingStatus, advancing it to the next status as appropriate.
    // It returns a boolean indicating whether the item is still valid and should be retained in the cache.
    // The boolean return is so that it works with `HashMap::retain` for efficiently dropping stale cache entries.
    fn update_backing_status(
        backing_status: &mut BackingStatus,
        notifier: &Sender<Notification>,
        extend: bool,
    ) -> bool {
        match backing_status {
            BackingStatus::Pending(p) => {
                log::debug!("processing pending {p:?}");
                match p.reply.try_recv() {
                    Ok(Ok(backing_id)) => {
                        let now = SystemTime::now();
                        *backing_status = BackingStatus::Ready(ReadyBackingId {
                            notifier: notifier.clone(),
                            backing_id,
                            timestamp: now,
                            reply_sender: None,
                        });
                        log::info!("Backing Id {backing_id} Ready");
                        true
                    }
                    Ok(Err(e)) => {
                        log::error!("error {e}");
                        false
                    }
                    Err(crossbeam_channel::TryRecvError::Empty) => {
                        log::debug!("waiting for reply");
                        true
                    }
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        log::warn!("channel disconnected");
                        false
                    }
                }
            }
            BackingStatus::Ready(r) => {
                let now = SystemTime::now();
                if extend {
                    log::debug!("processing ready {r:?}");
                    r.timestamp = now;
                    log::debug!("timestamp renewed");
                } else if now.duration_since(r.timestamp).unwrap() > BACKING_TIMEOUT {
                    log::debug!("processing ready {r:?}");
                    log::info!("Backing Id {} Timed Out", r.backing_id);
                    // everything below this is just for extra logging.
                    let (tx, rx) = crossbeam_channel::bounded(1);
                    r.reply_sender = Some(tx);
                    *backing_status = BackingStatus::Closed(ClosedBackingId { reply: rx });
                }
                true // ready remains ready or transitions to closed. either way, it remains in the cache.
            }
            BackingStatus::Closed(d) => {
                // all of this is just for the extra logging
                log::debug!("processing closed {d:?}");
                match d.reply.try_recv() {
                    Ok(Ok(value)) => {
                        log::debug!("ok {value:?}");
                        false
                    }
                    Ok(Err(e)) => {
                        log::error!("error {e}");
                        false
                    }
                    Err(crossbeam_channel::TryRecvError::Empty) => {
                        log::debug!("waiting for reply");
                        true
                    }
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        log::warn!("channel disconnected");
                        false
                    }
                }
            }
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
        config.add_capabilities(consts::FUSE_PASSTHROUGH)
            .expect("FUSE Kernel did not advertise support for passthrough (required for this example).");
        config.set_max_stack_depth(2).unwrap();
        Ok(config)
    }

    #[cfg(feature = "abi-7-11")]
    fn init_notification_sender(
        &mut self,
        sender: Sender<Notification>,
    ) -> bool {
        log::info!("init_notification_sender");
        self.notification_sender = Some(sender);
        true
    }

    // It is not generally safe to contact the kernel to obtain a backing id
    // while the kernel is waiting for a response to an open operation in progress.
    // Therefore, this example requests the backing id on lookup instead of on open.
    #[allow(clippy::cast_sign_loss)]
    fn lookup(&mut self, _req: RequestMeta, parent: u64, name: &Path) -> Result<Entry, Errno> {
        log::info!("lookup(name={name:?})");
        if parent == 1 && name.to_str() == Some("passthrough") {
            if self.get_update_backing_status(2).is_none() {
                log::info!("new pending backing id request");
                if let Some(sender) = &self.notification_sender {
                    let (tx, rx) = crossbeam_channel::bounded(1);
                    let file = File::open("/etc/profile").unwrap();
                    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
                    if let Err(e) = sender.send(Notification::OpenBacking((fd as u32, Some(tx)))) {
                        log::error!("failed to send OpenBacking notification: {e}");
                    } else {
                        let backing_id = PendingBackingId {
                            reply: rx,
                            _file: Arc::new(file),
                        };
                        self.backing_cache
                            .insert(2, BackingStatus::Pending(backing_id));
                    }
                } else {
                    log::warn!("unable to request a backing id. no notification sender available");
                }
            }
            Ok(Entry {
                ino: self.passthrough_file_attr.ino,
                generation: None,
                file_ttl: TTL,
                attr: self.passthrough_file_attr,
                attr_ttl: TTL,
            })
        } else {
            Err(Errno::ENOENT)
        }
    }

    fn getattr(&mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: Option<u64>,
    ) -> Result<(FileAttr, Duration), Errno> {
        match ino {
            1 => Ok((self.root_attr, TTL)),
            2 => Ok((self.passthrough_file_attr, TTL)),
            _ =>Err(Errno::ENOENT),
        }
    }

    fn open(&mut self, _req: RequestMeta, ino: u64, _flags: i32) -> Result<Open, Errno> {
        if ino != 2 {
            return Err(Errno::ENOENT);
        }
        // Check if a backing id is ready for this file
        let backing_id_option = if let Some(BackingStatus::Ready(ready_backing_id)) =
            self.get_update_backing_status(ino)
        {
            Some(ready_backing_id.backing_id)
        } else {
            //TODO: return Err(Errno::EAGAIN);
            None
        };
        let fh = self.next_fh();
        // TODO: track file handles
        log::info!("open: fh {fh}, backing_id_option {backing_id_option:?}");
        Ok(Open {
            fh,
            flags: consts::FOPEN_PASSTHROUGH,
            backing_id: backing_id_option,
        })
    }

    // The heartbeat function is called periodically by the FUSE session.
    // We use it to ensure that the cache entries have accurate timestamps.
    fn heartbeat(&mut self) -> Result<fuser::FsStatus, Errno> {
        if let Some(notifier) = self.notification_sender.clone() {
            self.backing_cache
                .retain(|_, v| PassthroughFs::update_backing_status(v, &notifier, false));
        }
        Ok(fuser::FsStatus::Ready)
    }

    // This deliberately unimplemented read() function proves that the example demonstrates passthrough.
    // If a user is able to read the file, it could only have been via the kernel.
    fn read<'a>(
        &mut self,
        _req: RequestMeta,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        _size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
    ) -> Result<Bytes<'a>, Errno> {
        unimplemented!();
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn readdir<'dir, 'name>(
        &mut self,
        _req: RequestMeta,
        ino: u64,
        _fh: u64,
        offset: i64,
        _max_bytes: u32
    ) -> Result<DirentList<'dir, 'name>, Errno> {
        if ino != 1 {
            return Err(Errno::ENOENT);
        }
        // In this example, return up to three entries depending on the offset.
        if (0..=2).contains(&offset) {
            // Case: offset in range:
            // Return a borrowed ('static) slice of entries.
            Ok((&ROOT_DIR_ENTRIES[offset as usize..]).into())
        } else {
            // Case: offset out of range:
            // No need to allocate anything; just use the Empty enum case.
            Ok(DirentList::Empty)
        }
    }

    fn release(
        &mut self,
        _req: RequestMeta,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
    ) -> Result<(), Errno> {
        // TODO: mark fh as unused
        Ok(())
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
    let mut session = fuser::Session::new(fs, Path::new(mountpoint), &options).unwrap();
    if let Err(e) = session.run_with_notifications() {
        // Since there is no graceful shutdown button, an error here is inevitable.
        log::info!("Session ended with error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_meta() -> RequestMeta {
        RequestMeta { unique: 0, uid: 1000, gid: 1000, pid: 2000 }
    }

    #[test]
    fn test_lookup_heartbeat_cycle() {
        let mut fs = PassthroughFs::new();
        let (tx, rx) = crossbeam_channel::unbounded();
        fs.init_notification_sender(tx);

        // Should react to lookup with a pending entry and a notification
        fs.lookup(dummy_meta(), 1, &PathBuf::from("passthrough")).unwrap();
        assert_eq!(fs.backing_cache.len(), 1);
        assert!(matches!(
            fs.backing_cache.get(&2).unwrap(),
            BackingStatus::Pending(_)
        ));
        let notification = rx.try_recv().unwrap();
        let (fd, sender) = match notification {
            Notification::OpenBacking(d) => d,
            _ => panic!("unexpected notification"),
        };
        assert!(fd > 0);
        let sender = sender.unwrap();

        // Heartbeat should not do anything yet
        fs.heartbeat().unwrap();
        assert_eq!(fs.backing_cache.len(), 1);
        assert!(matches!(
            fs.backing_cache.get(&2).unwrap(),
            BackingStatus::Pending(_)
        ));

        // Simulate the kernel replying to the open backing request
        sender.send(Ok(123)).unwrap();

        // Heartbeat should now trigger the transition to ready
        fs.heartbeat().unwrap();
        assert_eq!(fs.backing_cache.len(), 1);
        assert!(matches!(
            fs.backing_cache.get(&2).unwrap(),
            BackingStatus::Ready(_)
        ));

        // Open the file
        let open = fs.open(dummy_meta(), 2, 0).unwrap();
        assert_eq!(open.flags, consts::FOPEN_PASSTHROUGH);
        assert_eq!(open.backing_id, Some(123));

        // Wait for timeout
        std::thread::sleep(BACKING_TIMEOUT);

        // Heartbeat should now trigger the transition to closed
        fs.heartbeat().unwrap();
        assert_eq!(fs.backing_cache.len(), 1);
        assert!(matches!(
            fs.backing_cache.get(&2).unwrap(),
            BackingStatus::Closed(_)
        ));

        // Simulate the kernel replying to the close backing request
        let notification = rx.try_recv().unwrap();
        let (backing_id, sender) = match notification {
            Notification::CloseBacking(d) => d,
            _ => panic!("unexpected notification"),
        };
        assert_eq!(backing_id, 123);
        sender.unwrap().send(Ok(0)).unwrap();

        // Heartbeat should now trigger dropping the entry
        fs.heartbeat().unwrap();
        assert_eq!(fs.backing_cache.len(), 0);
    }
}
