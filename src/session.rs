//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use std::borrow::Cow;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::thread::{self};

use libc::EAGAIN;
use libc::EINTR;
use libc::ENODEV;
use libc::ENOENT;
use log::debug;
use log::error;
use log::info;
use nix::unistd::Uid;
use nix::unistd::geteuid;
use parking_lot::Mutex;

use crate::Errno;
use crate::Filesystem;
use crate::KernelConfig;
use crate::MountOption;
use crate::ReplyEmpty;
use crate::Request;
use crate::channel::Channel;
use crate::channel::ChannelSender;
use crate::dev_fuse::DevFuse;
use crate::ll;
use crate::ll::Operation;
use crate::ll::Response;
use crate::ll::Version;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi as abi;
use crate::mnt::Mount;
use crate::notify::Notifier;
use crate::reply::Reply;
use crate::reply::ReplyRaw;
use crate::reply::ReplySender;
use crate::request::RequestWithSender;

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub(crate) const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to `MAX_WRITE_SIZE` bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

#[derive(Default, Debug, Eq, PartialEq)]
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
    /// Filesystem operation implementations. None after `destroy` called.
    pub(crate) filesystem: Option<FS>,
    /// Communication channel to the kernel driver
    pub(crate) ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement `allow_root` and `auto_unmount`
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: Uid,
    /// FUSE protocol version, as reported by the kernel.
    /// The field is set to `Some` when the init message is received.
    pub(crate) proto_version: Option<Version>,
}

impl<FS: Filesystem> AsFd for Session<FS> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ch.as_fd()
    }
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    /// # Errors
    /// Returns an error if the options are incorrect, or if the fuse device can't be mounted.
    pub fn new<P: AsRef<Path>>(
        filesystem: FS,
        mountpoint: P,
        options: &[MountOption],
    ) -> io::Result<Session<FS>> {
        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther, return an error
        // because fusermount needs allow_root or allow_other to handle the auto_unmount option
        if options.contains(&MountOption::AutoUnmount)
            && !(options.contains(&MountOption::AllowRoot)
                || options.contains(&MountOption::AllowOther))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "auto_unmount requires allow_root or allow_other",
            ));
        }
        let (file, mount) = Mount::new(mountpoint, options)?;

        let ch = Channel::new(file);
        let allowed = if options.contains(&MountOption::AllowRoot) {
            SessionACL::RootAndOwner
        } else if options.contains(&MountOption::AllowOther) {
            SessionACL::All
        } else {
            SessionACL::Owner
        };

        Ok(Session {
            filesystem: Some(filesystem),
            ch,
            mount: Arc::new(Mutex::new(Some((mountpoint.to_owned(), mount)))),
            allowed,
            session_owner: geteuid(),
            proto_version: None,
        })
    }

    /// Wrap an existing /dev/fuse file descriptor. This doesn't mount the
    /// filesystem anywhere; that must be done separately.
    pub fn from_fd(filesystem: FS, fd: OwnedFd, acl: SessionACL) -> Self {
        let ch = Channel::new(Arc::new(DevFuse(File::from(fd))));
        Session {
            filesystem: Some(filesystem),
            ch,
            mount: Arc::new(Mutex::new(None)),
            allowed: acl,
            session_owner: geteuid(),
            proto_version: None,
        }
    }

    /// Run the session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        let sender = self.ch.sender();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *self.mount.lock()).map(|(_, mount)| mount);
        let guard = thread::spawn(move || self.run());
        Ok(BackgroundSession {
            guard,
            sender,
            mount,
        })
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    /// # Errors
    /// Returns any final error when the session comes to an end.
    pub(crate) fn run(mut self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(&mut buffer, align_of::<abi::fuse_in_header>());

        self.handshake(buf)?;

        let ret = self.event_loop(buf);

        if let Some(mut filesystem) = self.filesystem.take() {
            filesystem.destroy();
        }

        match ret {
            Err(e) => Err(e),
            Ok(None) => Ok(()),
            Ok(Some(destroy_reply)) => {
                destroy_reply.ok();
                Ok(())
            }
        }
    }

    /// Return `Some` if reply to `FUSE_DESTROY` needs to be sent.
    fn event_loop(&self, buf: &mut [u8]) -> io::Result<Option<ReplyEmpty>> {
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive(buf) {
                Ok(size) => match RequestWithSender::new(self.ch.sender(), &buf[..size]) {
                    // Dispatch request
                    Some(req) => {
                        if let Ok(Operation::Destroy(_)) = req.request.operation() {
                            return Ok(Some(req.reply()));
                        } else {
                            req.dispatch(self)
                        }
                    }
                    // Quit loop on illegal request
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid request",
                        ));
                    }
                },
                Err(err) => match err.raw_os_error() {
                    Some(
                          ENOENT // Operation interrupted. Accordingly to FUSE, this is safe to retry
                        | EINTR // Interrupted system call, retry
                        | EAGAIN // Explicitly instructed to try again
                    ) => continue,
                    Some(ENODEV) => return Ok(None),
                    // Unhandled error
                    _ => return Err(err),
                },
            }
        }
    }

    fn handshake(&mut self, buf: &mut [u8]) -> io::Result<()> {
        loop {
            // Read the init request from the kernel
            let size = match self.ch.receive(buf) {
                Ok(size) => size,
                Err(err) => match err.raw_os_error() {
                    Some(ENOENT | EINTR | EAGAIN) => continue,
                    Some(ENODEV) => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "FUSE device disconnected during handshake",
                        ));
                    }
                    _ => return Err(err),
                },
            };

            // Parse the request
            let request = match ll::AnyRequest::try_from(&buf[..size]) {
                Ok(request) => request,
                Err(err) => {
                    error!("{err}");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err.to_string()));
                }
            };

            // Extract the init operation
            let op = match request.operation() {
                Ok(op) => op,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Failed to parse FUSE operation",
                    ));
                }
            };

            let init = match op {
                ll::Operation::Init(init) => init,
                _ => {
                    error!("Received non-init FUSE operation before init: {}", request);
                    // Send error response and return error - non-init during handshake is invalid
                    let response = Response::new_error(ll::Errno::EIO);
                    <ReplyRaw as Reply>::new(
                        request.unique(),
                        ReplySender::Channel(self.ch.sender()),
                    )
                    .send_ll(&response);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Received non-init FUSE operation during handshake",
                    ));
                }
            };

            let v = init.version();
            if v.0 > abi::FUSE_KERNEL_VERSION {
                // Kernel has a newer major version than we support.
                // Send our version and wait for a second INIT request with a compatible version.
                debug!(
                    "INIT: Kernel version {} > our version {}, sending our version and waiting for next init",
                    v.0,
                    abi::FUSE_KERNEL_VERSION
                );
                let response = init.reply_version_only();
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&response);
                continue;
            }

            // We don't support ABI versions before 7.6
            if v < Version(7, 6) {
                error!("Unsupported FUSE ABI version {v}");
                let response = Response::new_error(ll::Errno::EPROTO);
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&response);
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("Unsupported FUSE ABI version {v}"),
                ));
            }

            let mut config = KernelConfig::new(init.capabilities(), init.max_readahead(), v);

            // Call filesystem init method and give it a chance to return an error
            let Some(filesystem) = &mut self.filesystem else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Bug: filesystem must be initialized during handshake",
                ));
            };
            let res = filesystem.init(Request::ref_cast(request.header()), &mut config);
            if let Err(error) = res {
                let errno = Errno::from_i32(error.raw_os_error().unwrap_or(0));
                let response = Response::new_error(errno);
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&response);
                return Err(error);
            }

            // Remember the ABI version supported by kernel and mark the session initialized.
            self.proto_version = Some(v);

            // Log capability status for debugging
            for bit in 0..64 {
                let bitflags = InitFlags::from_bits_retain(1 << bit);
                if bitflags == InitFlags::FUSE_INIT_EXT {
                    continue;
                }
                let bitflag_is_known = InitFlags::all().contains(bitflags);
                let kernel_supports = init.capabilities().contains(bitflags);
                let we_requested = config.requested.contains(bitflags);
                // On macOS, there's a clash between linux and macOS constants,
                // so we pick macOS ones (last).
                let name = if let Some((name, _)) = bitflags.iter_names().last() {
                    Cow::Borrowed(name)
                } else {
                    Cow::Owned(format!("(1 << {bit})"))
                };
                if we_requested && kernel_supports {
                    debug!("capability {name} enabled")
                } else if we_requested {
                    debug!("capability {name} not supported by kernel")
                } else if kernel_supports {
                    debug!("capability {name} not requested by client")
                } else if bitflag_is_known {
                    debug!("capability {name} not supported nor requested")
                }
            }

            // Reply with our desired version and settings.
            debug!(
                "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                abi::FUSE_KERNEL_VERSION,
                abi::FUSE_KERNEL_MINOR_VERSION,
                init.capabilities() & config.requested,
                config.max_readahead,
                config.max_write
            );

            let response = init.reply(&config);
            <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                .send_ll(&response);

            return Ok(());
        }
    }

    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        if let Some((_path, mount)) = std::mem::take(&mut *self.mount.lock()) {
            mount.umount()?;
        }
        Ok(())
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
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
        if let Some((_path, mount)) = std::mem::take(&mut *self.mount.lock()) {
            mount.umount()?;
        }
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

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop(&mut self) {
        if let Some(mut filesystem) = self.filesystem.take() {
            filesystem.destroy();
        }

        if let Some((mountpoint, _mount)) = std::mem::take(&mut *self.mount.lock()) {
            info!("unmounting session at {}", mountpoint.display());
        }
    }
}

/// The background session data structure
#[derive(Debug)]
pub struct BackgroundSession {
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    sender: ChannelSender,
    /// Ensures the filesystem is unmounted when the session ends
    mount: Option<Mount>,
}

impl BackgroundSession {
    /// Unmount the filesystem and join the background thread.
    pub fn umount_and_join(self) -> io::Result<()> {
        let Self {
            guard,
            sender: _,
            mount,
        } = self;
        if let Some(mount) = mount {
            mount.umount()?;
        }
        guard
            .join()
            .map_err(|_panic: Box<dyn std::any::Any + Send>| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "filesystem background thread panicked",
                )
            })?
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.sender.clone())
    }
}
