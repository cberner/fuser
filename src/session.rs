//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
#[allow(unused_imports)]
use log::{debug, info, warn, error};
use nix::unistd::geteuid;
use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::io;

use crate::ll::fuse_abi as abi;
use crate::request::Request;
use crate::{Filesystem, FsStatus};
use crate::MountOption;
use crate::{channel::Channel, mnt::Mount};
#[cfg(feature = "abi-7-11")]
use crate::notify::{Notification, Notifier};
#[cfg(feature = "abi-7-11")]
use crossbeam_channel::{Sender, Receiver};


/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to `MAX_WRITE_SIZE` bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

/// This value is used to prevent a busy loop in the synchronous run with notification
const SYNC_SLEEP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

#[derive(Default, Eq, PartialEq, Debug)]
/// How requests should be filtered based on the calling UID.
pub enum SessionACL {
    /// Allow requests from any user. Corresponds to the `allow_other` mount option.
    All,
    /// Allow requests from root. Corresponds to the `allow_root` mount option.
    RootAndOwner,
    /// Allow requests from the owning UID. This is FUSE's default mode of operation.
    #[default]
    Owner,
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations
    pub(crate) filesystem: FS,
    /// Communication channel to the kernel driver
    pub(crate) ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement `allow_root` and `auto_unmount`
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: u32,
    /// FUSE protocol major version
    pub(crate) proto_major: u32,
    /// FUSE protocol minor version
    pub(crate) proto_minor: u32,
    /// True if the filesystem is initialized (init operation done)
    pub(crate) initialized: bool,
    /// True if the filesystem was destroyed (destroy operation done)
    pub(crate) destroyed: bool,
    #[cfg(feature = "abi-7-11")]
    /// Whether this session currently has notification support
    pub(crate) notify: bool,
    #[cfg(feature = "abi-7-11")]
    /// Sender for poll events to the filesystem. It will be cloned and passed to Filesystem.
    pub(crate) ns: Sender<Notification>,
    #[cfg(feature = "abi-7-11")]
    /// Receiver for poll events from the filesystem.
    pub(crate) nr: Receiver<Notification>,
}

impl<FS: Filesystem> AsFd for Session<FS> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ch.as_fd()
    }
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    pub fn new<P: AsRef<Path>>(
        filesystem: FS,
        mountpoint: P,
        options: &[MountOption],
    ) -> io::Result<Session<FS>> {
        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther we enforce the ACL
        // ourself and implicitly set AllowOther because fusermount needs allow_root or allow_other
        // to handle the auto_unmount option
        let (file, mount) = if options.contains(&MountOption::AutoUnmount)
            && !(options.contains(&MountOption::AllowRoot)
                || options.contains(&MountOption::AllowOther))
        {
            warn!("Given auto_unmount without allow_root or allow_other; adding allow_other, with userspace permission handling");
            let mut modified_options = options.to_vec();
            modified_options.push(MountOption::AllowOther);
            Mount::new(mountpoint, &modified_options)?
        } else {
            Mount::new(mountpoint, options)?
        };
        // Create the channel for fuse messages
        let ch = Channel::new(file);
        let allowed = if options.contains(&MountOption::AllowRoot) {
            SessionACL::RootAndOwner
        } else if options.contains(&MountOption::AllowOther) {
            SessionACL::All
        } else {
            SessionACL::Owner
        };
        #[cfg(feature = "abi-7-11")]
        let mut filesystem = filesystem;
        #[cfg(feature = "abi-7-11")]
        // Create the channel for poll events.
        let (ns, nr) = crossbeam_channel::unbounded();
        #[cfg(feature = "abi-7-11")]
        // Pass the sender to the filesystem.
        let notify = filesystem.init_notification_sender(ns.clone());
        let new_session = Session {
            filesystem,
            ch,
            mount: Arc::new(Mutex::new(Some((mountpoint.to_owned(), mount)))),
            allowed,
            session_owner: geteuid().as_raw(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
            #[cfg(feature = "abi-7-11")]
            notify,
            #[cfg(feature = "abi-7-11")]
            ns,
            #[cfg(feature = "abi-7-11")]
            nr,
        };
        Ok(new_session)
    }

    /// Wrap an existing /dev/fuse file descriptor. This doesn't mount the
    /// filesystem anywhere; that must be done separately.
    pub fn from_fd(filesystem: FS, fd: OwnedFd, acl: SessionACL) -> Self {
        // Create the channel for fuse messages
        let ch = Channel::new(Arc::new(fd.into()));
        #[cfg(feature = "abi-7-11")]
        let mut filesystem = filesystem;
        #[cfg(feature = "abi-7-11")]
        // Create the channel for poll events.
        let (ns, nr) = crossbeam_channel::unbounded();
        #[cfg(feature = "abi-7-11")]
        // Pass the sender to the filesystem.
        let notify = filesystem.init_notification_sender(ns.clone());
        Session {
            filesystem,
            ch,
            mount: Arc::new(Mutex::new(None)),
            allowed: acl,
            session_owner: geteuid().as_raw(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
            #[cfg(feature = "abi-7-11")]
            notify,
            #[cfg(feature = "abi-7-11")]
            ns,
            #[cfg(feature = "abi-7-11")]
            nr,
        }
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    pub fn run(&mut self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(
            &mut buffer,
            std::mem::align_of::<abi::fuse_in_header>(),
        );
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive(buf) {
                Ok(size) => match Request::new(self.ch.sender(), &buf[..size]) {
                    // Dispatch request
                    Some(req) => req.dispatch(self),
                    // Quit loop on illegal request
                    None => break,
                },
                Err(err) => match err.raw_os_error() {
                    // Operation interrupted. Accordingly to FUSE, this is safe to retry
                    Some(ENOENT) => continue,
                    // Interrupted system call, retry
                    Some(EINTR) => continue,
                    // Explicitly try again
                    Some(EAGAIN) => continue,
                    // Filesystem was unmounted, quit the loop
                    Some(ENODEV) => break,
                    // Unhandled error
                    _ => return Err(err),
                },
            }
            // TODO: maybe add a heartbeat?
        }
        Ok(())
    }

    /// Unmount the filesystem
    pub fn unmount(&mut self) {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
    }

    /// Returns an object that can be used to send poll event notifications
    #[cfg(feature = "abi-7-11")]
    pub fn get_notification_sender(&self) -> Sender<Notification> {
        self.ns.clone()
    }

    /// Run the session loop in a single thread, same as `run()`, but additionally
    /// processing both FUSE requests and poll events without blocking.
    pub fn run_with_notifications(&mut self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel
        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(
            &mut buffer,
            std::mem::align_of::<abi::fuse_in_header>(),
        );

        info!("Running FUSE session in single-threaded mode");

        loop {
            let mut work_done = false;
            // Check for outgoing Notifications (non-blocking)
            #[cfg(feature = "abi-7-11")]
            if self.handle_notifications()? {
                work_done = true;
            }

            if work_done {
                // skip checking for incoming FUSE requests,
                // to prioritize checking for additional outgoing messages
                continue;
            }
            // Check for incoming FUSE requests (non-blocking)
            match self.ch.ready() {
                Err(err) => {
                    if err.raw_os_error() == Some(EINTR) {
                        debug!("FUSE fd connection interrupted, will retry.");
                    } else {
                        warn!("FUSE fd connection: {err}");
                        // Assume very bad. Stop the run. TODO: maybe some handling.
                        return Err(err);
                    }
                }
                Ok(ready) => {
                    if ready {
                        // Read a FUSE request (blocks until read succeeds)
                        match self.ch.receive(buf) {
                            Ok(size) => {
                                if size == 0 {
                                    // Read of 0 bytes on FUSE FD typically means it was closed (unmounted)
                                    info!("FUSE channel read 0 bytes, session ending.");
                                    break;
                                }
                                if let Some(req) = Request::new(self.ch.sender(), &buf[..size]) {
                                    req.dispatch(self);
                                } else {
                                    // Illegal request, quit loop
                                    warn!("Failed to parse FUSE request, session ending.");
                                    break;
                                }
                                work_done = true;
                            }
                            Err(err) => match err.raw_os_error() {
                                Some(ENOENT) => {
                                    debug!("FUSE channel receive ENOENT, retrying.");
                                    continue;
                                }
                                Some(EINTR) => {
                                    debug!("FUSE channel receive EINTR, retrying.");
                                    continue;
                                }
                                Some(EAGAIN) => {
                                    debug!("FUSE channel receive EAGAIN, retrying.");
                                    continue;
                                }
                                Some(ENODEV) => {
                                    info!("FUSE device not available (ENODEV), session ending.");
                                    break; // Filesystem was unmounted
                                }
                                _ => {
                                    error!("Error receiving FUSE request: {err}");
                                    return Err(err); // Unhandled error
                                }
                            },
                        }
                    }
                    // if not ready, do nothing.
                }
            }
            if !work_done {
                // No actions taken this loop iteration.
                // Sleep briefly to yield CPU.
                std::thread::sleep(SYNC_SLEEP_INTERVAL);
                // Do a heartbeat to let the Filesystem know that some time has passed.
                match FS::heartbeat(&mut self.filesystem) {
                    Ok(status) => {
                        if let FsStatus::Stopped = status {
                            break;
                        }
                        // TODO: handle other cases
                    }
                    Err(e) => {
                        warn!("Heartbeat error: {e:?}");
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "abi-7-11")]
    fn handle_notifications(&mut self) -> io::Result<bool> {
        if self.notify {
            match self.nr.try_recv() {
                Ok(notification) => {
                    debug!("Notification: {:?}", &notification);
                    if let Notification::Stop = notification {
                        // Filesystem says no more notifications.
                        info!("Filesystem sent Stop notification; disabling notifications.");
                        self.notify = false;
                    }
                    if let Err(_e) = self.notifier().notify(notification) {
                        error!("Failed to send notification.");
                        // TODO. Decide if error is fatal. ENODEV might mean unmounted.
                    }
                    Ok(true)
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    // No poll events pending, proceed to check FUSE FD
                    Ok(false)
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    // Filesystem's Notification Sender disconnected.
                    // This is not necessarily a fatal error for the session itself,
                    // as FUSE requests can still be processed.
                    warn!("Notification channel disconnected.");
                    self.notify = false;
                    Ok(false)
                }
            }
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct SessionUnmounter {
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
}

impl SessionUnmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
        Ok(())
    }
}

fn aligned_sub_buf(buf: &mut [u8], alignment: usize) -> &mut [u8] {
    let off = alignment - (buf.as_ptr() as usize) % alignment;
    if off == alignment {
        buf
    } else {
        &mut buf[off..]
    }
}

/// A session can be run synchronously in the current thread using `run()` or spawned into a
/// background thread using `spawn()`.
impl<FS: 'static + Filesystem + Send> Session<FS> {
    /// Run the session loop in a background thread
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        BackgroundSession::new(self)
    }
}

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop(&mut self) {
        if !self.destroyed {
            self.filesystem.destroy();
            self.destroyed = true;
        }

        if let Some((mountpoint, _mount)) = std::mem::take(&mut *self.mount.lock().unwrap()) {
            info!("unmounting session at {}", mountpoint.display());
        }
    }
}

/// The background session data structure
pub struct BackgroundSession {
    /// Thread guard of the main session loop
    pub main_loop_guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    #[cfg(feature = "abi-7-11")]
    sender: Sender<Notification>,
    /// Ensures the filesystem is unmounted when the session ends
    _mount: Option<Mount>,
}

impl BackgroundSession {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn new<FS: Filesystem + Send + 'static>(mut se: Session<FS>) -> io::Result<BackgroundSession> {
        #[cfg(feature = "abi-7-11")]
        let sender = se.ns.clone();

        let mount = std::mem::take(&mut *se.mount.lock().unwrap()).map(|(_, mount)| mount);

        #[cfg(not(feature = "abi-7-11"))]
        // The main session (se) is moved into this thread.
        let main_loop_guard = thread::spawn(move || {
            se.run()
        });
        #[cfg(feature = "abi-7-11")]
        let main_loop_guard = thread::spawn(move || {
            se.run_with_notifications()
        });

        Ok(BackgroundSession {
            main_loop_guard,
            #[cfg(feature = "abi-7-11")]
            sender,
            _mount: mount,
        })
    }
    /// Unmount the filesystem and join the background thread.
    pub fn join(self) {
        let Self {
            main_loop_guard,
            #[cfg(feature = "abi-7-11")]
            sender: _,
            _mount,
        } = self;
        // Unmount the filesystem
        drop(_mount);
        // Stop the background thread
        let res = main_loop_guard.join()
            .expect("Failed to join the background thread");
        // An error is expected, since the thread was active when the unmount occured.
        info!("Session loop end with result {res:?}.");
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    #[must_use]
    pub fn get_notification_sender(&self) -> Sender<Notification> {
       self.sender.clone()
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let mut builder = f.debug_struct("BackgroundSession");
        builder.field("main_loop_guard", &self.main_loop_guard);
        #[cfg(feature = "abi-7-11")]
        {
            builder.field("sender", &self.sender);
        }
        builder.field("_mount", &self._mount);
        builder.finish()
    }
}
