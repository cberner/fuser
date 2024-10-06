//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::error;
use nix::unistd::geteuid;
use std::fmt;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::{io, ops::DerefMut};

use crate::channel::Channel;
use crate::ll::fuse_abi as abi;
use crate::request::Request;
use crate::sys;
use crate::Filesystem;
use crate::MountOption;

#[cfg(feature = "abi-7-11")]
use crate::{channel::ChannelSender, notify::Notifier};

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to MAX_WRITE_SIZE bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

/// A mountpoint, bound to a /dev/fuse file descriptor. Unmounts the filesystem
/// on drop.
pub struct Mount {
    mountpoint: PathBuf,
    fuse_device: OwnedFd,
    auto_unmount_socket: Option<UnixStream>,
}

impl std::fmt::Debug for Mount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Mount").field(&self.mountpoint).finish()
    }
}

impl Mount {
    /// Creates a new mount for the given device FD (which can be wrapped in a
    /// [Session]).
    ///
    /// Mounting requires CAP_SYS_ADMIN.
    pub fn new(
        device_fd: impl AsFd,
        mountpoint: impl AsRef<Path>,
        options: &[MountOption],
    ) -> io::Result<Self> {
        let mountpoint = mountpoint.as_ref().canonicalize()?;
        sys::mount(mountpoint.as_os_str(), device_fd.as_fd(), options)?;

        // Make a dup of the fuse device FD, so we can poll if the filesystem
        // is still mounted.
        let fuse_device = device_fd.as_fd().try_clone_to_owned()?;

        Ok(Self {
            mountpoint,
            fuse_device,
            auto_unmount_socket: None,
        })
    }

    /// Uses fusermount(1) to mount the filesystem. Unlike [Mount::new],
    /// fusermount opens the /dev/fuse FD for you, and it is returend as the
    /// first element of the tuple. This file descriptor can then be wrapped
    /// using [crate::Session::from_fd].
    pub fn new_fusermount(
        mountpoint: impl AsRef<Path>,
        options: &[MountOption],
    ) -> io::Result<(OwnedFd, Self)> {
        let mountpoint = mountpoint.as_ref().canonicalize()?;
        let (fd, sock) = sys::fusermount(mountpoint.as_os_str(), options)?;

        // Make a dup of the fuse device FD, so we can poll if the filesystem
        // is still mounted.
        let fuse_device = fd.as_fd().try_clone_to_owned()?;

        Ok((
            fd,
            Self {
                mountpoint,
                fuse_device,
                auto_unmount_socket: sock,
            },
        ))
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        use std::io::ErrorKind::PermissionDenied;
        if !sys::is_mounted(&self.fuse_device) {
            // If the filesystem has already been unmounted, avoid unmounting it again.
            // Unmounting it a second time could cause a race with a newly mounted filesystem
            // living at the same mountpoint
            return;
        }

        if let Some(sock) = std::mem::take(&mut self.auto_unmount_socket) {
            drop(sock);
            // fusermount in auto-unmount mode, no more work to do.
            return;
        }

        if let Err(err) = sys::umount(self.mountpoint.as_os_str()) {
            if err.kind() == PermissionDenied {
                // Linux always returns EPERM for non-root users.  We have to let the
                // library go through the setuid-root "fusermount -u" to unmount.
                sys::fusermount_umount(&self.mountpoint)
            } else {
                error!("Unmount failed: {}", err)
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Defines which processes should be allowed to interact with a filesystem.
pub enum SessionACL {
    /// Allow requests from all uids. Equivalent to allow_other.
    All,
    /// Allow requests from root (uid 0) and the session owner. Equivalent to allow_root.
    RootAndOwner,
    /// Allow only requests from the session owner. FUSE's default mode of operation.
    Owner,
}

impl SessionACL {
    pub(crate) fn from_mount_options(options: &[MountOption]) -> Self {
        if options.contains(&MountOption::AllowRoot) {
            SessionACL::RootAndOwner
        } else if options.contains(&MountOption::AllowOther) {
            SessionACL::All
        } else {
            SessionACL::Owner
        }
    }
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations
    pub(crate) filesystem: FS,
    /// Communication channel to the kernel driver
    ch: Channel,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement allow_root and auto_unmount
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
}

impl<FS: Filesystem> AsFd for Session<FS> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.ch.as_fd()
    }
}

impl<FS: Filesystem> Session<FS> {
    /// Creates a new session. This function does not mount the session; use
    /// [crate::mount2] or similar or use [Session::as_fd] to extract the
    /// /dev/fuse file descriptor and mount it separately.
    pub fn new(filesystem: FS, acl: SessionACL) -> io::Result<Self> {
        let device_fd = sys::open_device()?;
        Ok(Self::from_fd(device_fd, filesystem, acl))
    }

    /// Creates a new session, using an existing /dev/fuse file descriptor.
    pub fn from_fd(device_fd: OwnedFd, filesystem: FS, acl: SessionACL) -> Self {
        let ch = Channel::new(Arc::new(device_fd));

        Session {
            filesystem,
            ch,
            allowed: acl,
            session_owner: geteuid().as_raw(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
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
            buffer.deref_mut(),
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
        }
        Ok(())
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
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

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop(&mut self) {
        if !self.destroyed {
            self.filesystem.destroy();
            self.destroyed = true;
        }
    }
}

/// The background session data structure
pub struct BackgroundSession {
    /// Path of the mounted filesystem
    pub mountpoint: PathBuf,
    /// Unmounts the filesystem on drop
    mount: Arc<Mutex<Option<Mount>>>,
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    #[cfg(feature = "abi-7-11")]
    sender: ChannelSender,
}

impl BackgroundSession {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub(crate) fn new<FS: Filesystem + Send + 'static>(
        se: Session<FS>,
        mount: Mount,
        mountpoint: impl AsRef<Path>,
    ) -> io::Result<BackgroundSession> {
        let mountpoint = mountpoint.as_ref().to_owned();

        #[cfg(feature = "abi-7-11")]
        let sender = se.ch.sender();

        let guard = thread::spawn(move || {
            let mut se = se;
            se.run()
        });

        Ok(BackgroundSession {
            mountpoint,
            mount: Arc::new(Mutex::new(Some(mount))),
            guard,
            #[cfg(feature = "abi-7-11")]
            sender,
        })
    }
    /// Unmount the filesystem and join the background thread.
    pub fn join(self) {
        let Self { guard, mount, .. } = self;

        drop(mount); // Unmounts the filesystem.
        guard.join().unwrap().unwrap();
    }

    /// Returns a thread-safe handle that can be used to unmount the
    /// filesystem.
    pub fn unmounter(&self) -> Unmounter {
        Unmounter {
            mount: Arc::downgrade(&self.mount),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.sender.clone())
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "BackgroundSession {{ mountpoint: {:?}, guard: JoinGuard<()> }}",
            self.mountpoint
        )
    }
}

#[derive(Debug, Clone)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct Unmounter {
    mount: Weak<Mutex<Option<Mount>>>,
}

impl Unmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        if let Some(mount) = self.mount.upgrade() {
            mount.lock().unwrap().take();
        }

        Ok(())
    }
}
