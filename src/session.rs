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
use std::sync::Arc;
use std::thread::JoinHandle;
use std::thread::{self};

use log::debug;
use log::error;
use log::info;
use log::warn;
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
use crate::ll::ResponseErrno;
use crate::ll::Version;
use crate::ll::flags::init_flags::InitFlags;
use crate::ll::fuse_abi as abi;
use crate::mnt::Mount;
use crate::mnt::mount_options::Config;
use crate::mnt::mount_options::check_option_conflicts;
use crate::notify::Notifier;
use crate::read_buf::FuseReadBuf;
use crate::reply::Reply;
use crate::reply::ReplyRaw;
use crate::reply::ReplySender;
use crate::request::RequestWithSender;

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub(crate) const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// The minimum write size the kernel will honor: process_init_reply() in the
/// kernel's fs/fuse/inode.c clamps a smaller negotiated max_write up to 4096,
/// so advertising less would not stop larger write requests from arriving.
pub(crate) const MIN_WRITE_SIZE: usize = 4096;

#[derive(Default, Debug, Eq, PartialEq, Clone, Copy)]
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

impl SessionACL {
    /// Returns the mount option string for kernel/fusermount/libfuse paths.
    /// Both `All` and `RootAndOwner` map to `allow_other` - the kernel only
    /// understands `allow_other`, and fuser enforces the root-only restriction internally.
    #[allow(dead_code)]
    pub(crate) fn to_mount_option(self) -> Option<&'static str> {
        match self {
            SessionACL::All | SessionACL::RootAndOwner => Some("allow_other"),
            SessionACL::Owner => None,
        }
    }
}

/// Calls `destroy` on drop.
#[derive(Debug)]
pub(crate) struct FilesystemHolder<FS: Filesystem> {
    pub(crate) fs: Option<FS>,
}

impl<FS: Filesystem> FilesystemHolder<FS> {
    fn destroy(&mut self) {
        if let Some(mut fs) = self.fs.take() {
            fs.destroy();
        }
    }
}

impl<FS: Filesystem> Drop for FilesystemHolder<FS> {
    fn drop(&mut self) {
        self.destroy();
    }
}

#[derive(Debug)]
struct UmountOnDrop {
    mount: Arc<Mutex<Option<Mount>>>,
}

impl UmountOnDrop {
    fn umount(&self) -> io::Result<()> {
        if let Some(mount) = self.mount.lock().take() {
            mount.umount()?;
        }
        Ok(())
    }
}

impl Drop for UmountOnDrop {
    fn drop(&mut self) {
        if let Err(e) = self.umount() {
            warn!("Failed to umount filesystem: {}", e);
        }
    }
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations. None after `destroy` called.
    pub(crate) filesystem: FilesystemHolder<FS>,
    /// Communication channel to the kernel driver
    pub(crate) ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: UmountOnDrop,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement `allow_root` and `auto_unmount`
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: Uid,
    /// FUSE protocol version, as reported by the kernel.
    /// The field is set to `Some` when the init message is received.
    pub(crate) proto_version: Option<Version>,
    /// Capabilities agreed with the kernel during init. Some request layouts depend on
    /// them, so the event loops need them to parse correctly
    pub(crate) negotiated: InitFlags,
    /// Everything the kernel advertised during init, whether or not it was requested.
    /// Some operations are honoured by the kernel without being negotiated, so this,
    /// not `negotiated`, says whether the kernel can perform them
    pub(crate) kernel_capabilities: InitFlags,
    pub(crate) config: Config,
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
        options: &Config,
    ) -> io::Result<Session<FS>> {
        check_option_conflicts(options)?;

        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther, return an error
        // because fusermount needs allow_root or allow_other to handle the auto_unmount option
        if options.mount_options.contains(&MountOption::AutoUnmount)
            && options.acl == SessionACL::Owner
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("auto_unmount requires acl != Owner, got: {:?}", options.acl),
            ));
        }
        let (file, mount) = Mount::new(mountpoint, &options.mount_options, options.acl)?;

        let ch = Channel::new(file);

        let mut session = Session {
            filesystem: FilesystemHolder {
                fs: Some(filesystem),
            },
            ch,
            mount: UmountOnDrop {
                mount: Arc::new(Mutex::new(Some(mount))),
            },
            allowed: options.acl,
            session_owner: geteuid(),
            proto_version: None,
            negotiated: InitFlags::empty(),
            kernel_capabilities: InitFlags::empty(),
            config: options.clone(),
        };

        session.handshake()?;

        Ok(session)
    }

    /// Wrap an existing /dev/fuse file descriptor. This doesn't mount the
    /// filesystem anywhere; that must be done separately.
    pub fn from_fd(
        filesystem: FS,
        fd: OwnedFd,
        acl: SessionACL,
        config: Config,
    ) -> io::Result<Self> {
        let ch = Channel::new(Arc::new(DevFuse(File::from(fd))));
        let mut session = Session {
            filesystem: FilesystemHolder {
                fs: Some(filesystem),
            },
            ch,
            mount: UmountOnDrop {
                mount: Arc::new(Mutex::new(None)),
            },
            allowed: acl,
            session_owner: geteuid(),
            proto_version: None,
            negotiated: InitFlags::empty(),
            kernel_capabilities: InitFlags::empty(),
            config,
        };

        session.handshake()?;

        Ok(session)
    }

    /// Run the session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the session is waited for, so that
    /// `Filesystem::destroy` has run when drop returns - except in the cases documented
    /// on [`BackgroundSession`], where the session thread is detached instead.
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        let sender = self.ch.sender();
        let fuse_device = self.ch.device();
        let kernel_capabilities = self.kernel_capabilities;
        let kernel_abi = self.proto_version;
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *self.mount.mount.lock());
        let guard = thread::Builder::new()
            .name("fuser-bg".to_string())
            .spawn(move || self.run())?;
        Ok(BackgroundSession {
            guard: Some(guard),
            sender,
            fuse_device,
            mount,
            kernel_capabilities,
            kernel_abi,
        })
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    /// # Errors
    /// Returns any final error when the session comes to an end.
    pub fn run(self) -> io::Result<()> {
        let Session {
            filesystem,
            ch,
            mount: _do_not_umount_yet,
            allowed,
            session_owner,
            proto_version,
            negotiated,
            kernel_capabilities,
            config,
        } = self;

        let n_threads = config.n_threads.unwrap_or(1);

        if !cfg!(target_os = "linux") && n_threads != 1 {
            // TODO: check whether it works on macOS/FreeBSD and enable if it works.
            return Err(io::Error::other(
                "n_threads != 1 is only supported on Linux",
            ));
        }

        let Some(n_threads_minus_one) = n_threads.checked_sub(1) else {
            return Err(io::Error::other("n_threads"));
        };

        let mut filesystem = Arc::new(filesystem);

        let mut channels = Vec::with_capacity(n_threads);

        for _ in 0..n_threads_minus_one {
            if config.clone_fd {
                #[cfg(target_os = "linux")]
                {
                    channels.push(ch.clone_fd()?);
                    continue;
                }
                #[cfg(not(target_os = "linux"))]
                {
                    return Err(io::Error::other("clone_fd is only supported on Linux"));
                }
            } else {
                channels.push(ch.clone());
            }
        }
        channels.push(ch);

        let mut threads = Vec::with_capacity(n_threads);

        for (i, ch) in channels.into_iter().enumerate() {
            let thread_name = format!("fuser-{i}");
            let event_loop = SessionEventLoop {
                thread_name: thread_name.clone(),
                filesystem: filesystem.clone(),
                ch,
                allowed,
                session_owner,
                negotiated,
                kernel_capabilities,
                kernel_abi: proto_version,
            };
            threads.push(
                thread::Builder::new()
                    .name(thread_name)
                    .spawn(move || event_loop.event_loop())?,
            );
        }

        let mut reply: io::Result<()> = Ok(());
        for thread in threads {
            let res = match thread.join() {
                Ok(res) => res,
                Err(_) => {
                    return Err(io::Error::other("event loop thread panicked"));
                }
            };
            if let Err(e) = res {
                if reply.is_ok() {
                    reply = Err(e);
                }
            }
        }

        let Some(filesystem) = Arc::get_mut(&mut filesystem) else {
            return Err(io::Error::other(
                "BUG: must have one refcount for filesystem",
            ));
        };

        filesystem.destroy();

        reply
    }

    fn handshake(&mut self) -> io::Result<()> {
        let mut buf = FuseReadBuf::new();
        let buf = buf.as_mut();

        loop {
            // Read the init request from the kernel
            let size = match self.ch.receive_retrying(buf) {
                Ok(size) => size,
                Err(nix::errno::Errno::ENODEV | nix::errno::Errno::ECONNABORTED) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "FUSE device disconnected during handshake",
                    ));
                }
                Err(err) => return Err(err.into()),
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
                    <ReplyRaw as Reply>::new(
                        request.unique(),
                        ReplySender::Channel(self.ch.sender()),
                    )
                    .send_ll(&ResponseErrno(ll::Errno::EIO));
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
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&ResponseErrno(ll::Errno::EPROTO));
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("Unsupported FUSE ABI version {v}"),
                ));
            }

            let mut config = KernelConfig::new(init.capabilities(), init.max_readahead(), v);

            // Call filesystem init method and give it a chance to return an error
            let Some(filesystem) = &mut self.filesystem.fs else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Bug: filesystem must be initialized during handshake",
                ));
            };
            let res = filesystem.init(Request::ref_cast(request.header()), &mut config);
            if let Err(error) = res {
                let errno = Errno::from_i32(error.raw_os_error().unwrap_or(0));
                <ReplyRaw as Reply>::new(request.unique(), ReplySender::Channel(self.ch.sender()))
                    .send_ll(&ResponseErrno(errno));
                return Err(error);
            }

            // Remember the ABI version supported by kernel and mark the session initialized.
            self.proto_version = Some(v);
            self.negotiated = init.capabilities() & config.requested;
            self.kernel_capabilities = init.capabilities();

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
        self.mount.umount()
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(
            self.ch.sender(),
            self.kernel_capabilities,
            self.proto_version,
        )
    }
}

#[derive(Debug)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct SessionUnmounter {
    mount: Arc<Mutex<Option<Mount>>>,
}

impl SessionUnmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        if let Some(mount) = std::mem::take(&mut *self.mount.lock()) {
            mount.umount()?;
        }
        Ok(())
    }
}

pub(crate) struct SessionEventLoop<FS: Filesystem> {
    /// Cache thread name for faster `debug!`.
    pub(crate) thread_name: String,
    pub(crate) ch: Channel,
    pub(crate) filesystem: Arc<FilesystemHolder<FS>>,
    pub(crate) allowed: SessionACL,
    pub(crate) session_owner: Uid,
    pub(crate) negotiated: InitFlags,
    pub(crate) kernel_capabilities: InitFlags,
    pub(crate) kernel_abi: Option<Version>,
}

impl<FS: Filesystem> SessionEventLoop<FS> {
    fn event_loop(&self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buf = FuseReadBuf::new();
        let buf = buf.as_mut();
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive_retrying(buf) {
                Ok(size) => {
                    match RequestWithSender::new(self.ch.sender(), &buf[..size], self.negotiated) {
                        // Dispatch request
                        Some(req) => {
                            if let Ok(Operation::Destroy(_)) = req.request.operation() {
                                req.reply::<ReplyEmpty>().ok();
                                return Ok(());
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
                    }
                }
                // The kernel returns ENODEV when the filesystem was unmounted, or
                // ECONNABORTED when the connection was aborted with FUSE_ABORT_ERROR
                // negotiated. Either way the connection is gone: a normal end of the
                // session, not an operation failure (issue #212)
                Err(nix::errno::Errno::ENODEV | nix::errno::Errno::ECONNABORTED) => return Ok(()),
                Err(err) => return Err(err.into()),
            }
        }
    }
}

/// The background session data structure
///
/// Dropping this unmounts the filesystem and blocks until the session has ended,
/// which guarantees that `Filesystem::destroy` has run when drop returns. Because
/// of that, it must not be dropped from within a filesystem callback, which runs
/// on the session thread being waited for. For a session created via
/// `Session::from_fd` there is no mount to remove, so dropping cannot end the
/// session and leaves its thread detached; end the session externally and use
/// `join` to wait for it instead. The thread is likewise left detached, with a
/// warning, rather than waiting for a session that may never end when the
/// unmount fails, or when the kernel connection is still alive a few seconds
/// after a successful unmount request (e.g. a lazily unmounted filesystem that
/// is still in use, or an unmount helper that failed without reporting it).
#[derive(Debug)]
pub struct BackgroundSession {
    /// Thread guard of the background session. None once joined.
    guard: Option<JoinHandle<io::Result<()>>>,
    /// Object for creating Notifiers for client use
    sender: ChannelSender,
    /// The FUSE device fd of the session's kernel connection
    fuse_device: Arc<DevFuse>,
    /// Ensures the filesystem is unmounted when the session ends
    mount: Option<Mount>,
    /// Everything the kernel advertised during init, for notifications whose support
    /// depends on it
    kernel_capabilities: InitFlags,
    /// The ABI version agreed during init, for notifications with no capability bit
    kernel_abi: Option<Version>,
}

/// How long teardown waits for the kernel connection to end after a successful
/// unmount request, before giving up on joining the session thread. The
/// connection can end asynchronously (auto_unmount, kernel teardown), but a few
/// seconds only pass without it ending when the session cannot be waited for,
/// e.g. a lazily unmounted filesystem still in use
const UNMOUNT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

impl BackgroundSession {
    /// Unmount the filesystem and join the background thread, returning the
    /// session result. `Filesystem::destroy` has run when this returns.
    pub fn umount_and_join(mut self) -> io::Result<()> {
        if let Some(mount) = self.mount.take() {
            if let Err(err) = mount.umount() {
                // The filesystem is still mounted and the session still running,
                // so joining would block indefinitely; leave the thread detached,
                // as before
                self.guard.take();
                return Err(err);
            }
        }
        self.join_impl()
    }

    /// Returns an object that can be used to send notifications to the kernel
    pub fn notifier(&self) -> Notifier {
        Notifier::new(
            self.sender.clone(),
            self.kernel_capabilities,
            self.kernel_abi,
        )
    }

    /// Join the filesystem thread without unmounting first: blocks until
    /// something else ends the session, e.g. an external unmount.
    pub fn join(mut self) -> io::Result<()> {
        self.join_impl()
    }

    fn join_impl(&mut self) -> io::Result<()> {
        let Some(guard) = self.guard.take() else {
            return Ok(());
        };
        guard
            .join()
            .map_err(|_panic: Box<dyn std::any::Any + Send>| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "filesystem background thread panicked",
                )
            })?
    }
}

impl Drop for BackgroundSession {
    fn drop(&mut self) {
        // Unmount and wait for the session to end, so that Filesystem::destroy
        // has run by the time drop returns (issues #239 and #411). Without the
        // join, the process could exit before the detached session thread got
        // around to calling destroy
        let Some(mount) = self.mount.take() else {
            // No mount to remove (Session::from_fd): nothing here can end the
            // session, so joining could block forever; leave the thread detached
            return;
        };
        if let Err(err) = mount.umount() {
            // Still mounted, so the session is still running and joining would
            // block indefinitely
            warn!("Failed to unmount filesystem during drop: {err}");
            return;
        }
        // The connection can end asynchronously (e.g. auto_unmount), and some
        // unmount helpers cannot report failures. Wait boundedly, and if the
        // session lives on, detach rather than block indefinitely
        if !crate::mnt::connection_ended(&self.fuse_device, UNMOUNT_WAIT) {
            warn!("FUSE connection still alive after unmount; detaching session thread");
            return;
        }
        if let Err(err) = self.join_impl() {
            warn!("Session ended with an error during drop: {err}");
        }
    }
}

// The abort test uses fusectl, which only exists on Linux; on other targets the
// whole module would be dead code
#[cfg(all(test, target_os = "linux"))]
mod test {
    use std::io::Write;
    use std::mem::ManuallyDrop;

    use super::*;
    use crate::Config;
    use crate::InitFlags;
    use crate::KernelConfig;
    use crate::Request;

    /// A filesystem that requests FUSE_ABORT_ERROR during init, so that after an
    /// abort the FUSE device fails reads with ECONNABORTED instead of ENODEV.
    struct AbortErrorFs;

    impl Filesystem for AbortErrorFs {
        fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
            // Ignore the error: on kernels without FUSE_ABORT_ERROR an abort
            // yields ENODEV, which ends the session cleanly anyway
            let _ = config.add_capabilities(InitFlags::FUSE_ABORT_ERROR);
            Ok(())
        }
    }

    /// Aborting the connection (via fusectl) with FUSE_ABORT_ERROR negotiated makes
    /// the FUSE device return ECONNABORTED. The session loop must treat that as a
    /// normal end of the session, so that umount_and_join() reports success rather
    /// than an error for an administratively aborted filesystem (issue #212).
    #[test]
    fn session_ends_cleanly_after_abort() {
        // Leak the directory on failure: it may still be a (dead) mountpoint
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        // The mount table lists the canonical path; resolve while it is a plain dir
        let mountpoint = tmp.path().canonicalize().unwrap();

        let session = Session::new(AbortErrorFs, &mountpoint, &Config::default()).unwrap();
        let bg = session.spawn().unwrap();

        // Wait until the handshake completed: the kernel forwards filesystem
        // requests only after the init reply was processed, so a completed
        // operation (the errno does not matter) proves the loop is past it
        let _ = std::fs::metadata(&mountpoint);

        let Some(abort_path) = fusectl_abort_path(&mountpoint) else {
            eprintln!("skipping session_ends_cleanly_after_abort: fusectl not available");
            bg.umount_and_join().unwrap();
            ManuallyDrop::into_inner(tmp);
            return;
        };
        std::fs::OpenOptions::new()
            .write(true)
            .open(abort_path)
            .unwrap()
            .write_all(b"1")
            .unwrap();

        bg.umount_and_join()
            .expect("session must end cleanly after the connection was aborted");

        // Teardown intentionally leaves the dead mount in the mount table (the
        // same as libfuse); detach it so the tempdir can be removed
        let _ = nix::mount::umount2(&mountpoint, nix::mount::MntFlags::MNT_DETACH);
        for fusermount in ["fusermount3", "fusermount"] {
            let _ = std::process::Command::new(fusermount)
                .args(["-u", "-q", "-z", "--"])
                .arg(&mountpoint)
                .status();
        }
        ManuallyDrop::into_inner(tmp);
    }

    /// A panic in init() must reach the caller with the filesystem unmounted. The
    /// handshake used to run inside the session loop, so with spawn() the caller was
    /// handed a live BackgroundSession while the kernel waited forever for an init
    /// reply that would never come, hanging every process that touched the mountpoint
    /// (issue #271). Running the handshake in Session::new() makes the panic unwind
    /// through it, unmounting on the way out.
    #[test]
    fn panic_in_init_leaves_nothing_mounted() {
        struct PanicInInit;
        impl Filesystem for PanicInInit {
            fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
                panic!("deliberate panic from a test filesystem's init()");
            }
        }

        // Leak the directory on failure: it may still be a mountpoint nothing serves
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        // The mount table lists the canonical path
        let mountpoint = tmp.path().canonicalize().unwrap();

        let session = std::panic::catch_unwind(|| {
            Session::new(PanicInInit, &mountpoint, &Config::default()).and_then(Session::spawn)
        });
        assert!(
            session.is_err(),
            "the panic must reach the caller, rather than a session thread it cannot see"
        );

        // Anything left mounted here has nothing serving it, so every access to the
        // mountpoint would block indefinitely
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        assert!(
            !mounts
                .lines()
                .any(|line| line.split(' ').nth(1) == mountpoint.to_str()),
            "the filesystem must not be left mounted with nothing serving it:\n{mounts}"
        );
        ManuallyDrop::into_inner(tmp);
    }

    /// The kernel fills a request's uid, gid and pid from the task that caused it, for
    /// every operation that goes through fuse_simple_request(). Every access decision
    /// fuser makes rests on that - SessionACL, and which operations are exempt from it
    /// because the kernel issues them with no caller - so it is worth pinning down rather
    /// than assuming. `FUSE_ARGS()` zero-initializes, so a header fuser had merely copied
    /// from there would carry uid 0 and pid 0.
    #[test]
    fn requests_carry_the_calling_task() {
        struct CallerFs {
            seen: Arc<Mutex<Option<(u32, u32)>>>,
        }
        impl Filesystem for CallerFs {
            fn getattr(
                &self,
                req: &Request,
                _ino: crate::INodeNo,
                _fh: Option<crate::FileHandle>,
                reply: crate::ReplyAttr,
            ) {
                *self.seen.lock() = Some((req.uid(), req.pid()));
                reply.error(Errno::ENOSYS);
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let bg = Session::new(
            CallerFs { seen: seen.clone() },
            &mountpoint,
            &Config::default(),
        )
        .unwrap()
        .spawn()
        .unwrap();

        // Any operation will do; this one is answered from the mountpoint's root inode
        let _ = std::fs::metadata(&mountpoint);
        let seen = seen.lock().take();
        drop(bg);
        ManuallyDrop::into_inner(tmp);

        let (uid, pid) = seen.expect("the filesystem must have been asked for the root inode");
        assert_eq!(
            uid,
            geteuid().as_raw(),
            "the request must carry the caller's uid"
        );
        // Discriminating even when the test runs as root, where the uid above is 0 either
        // way. The kernel takes this from task_pid(current), so it is the id of the thread
        // that made the call rather than of the process
        assert_eq!(
            pid,
            nix::unistd::gettid().as_raw() as u32,
            "the request must carry the calling thread's id"
        );
    }

    /// Dropping a BackgroundSession must unmount the filesystem and wait for the
    /// session to end, so that Filesystem::destroy has run when drop returns.
    #[test]
    fn drop_waits_for_destroy() {
        struct DestroyFs {
            destroyed: Arc<std::sync::atomic::AtomicBool>,
        }
        impl Filesystem for DestroyFs {
            fn destroy(&mut self) {
                // Give drop a chance to return early: without the join, drop
                // consistently wins this race and the assertion below fails
                std::thread::sleep(std::time::Duration::from_millis(200));
                self.destroyed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let destroyed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fs = DestroyFs {
            destroyed: destroyed.clone(),
        };
        let bg = Session::new(fs, tmp.path(), &Config::default())
            .unwrap()
            .spawn()
            .unwrap();
        drop(bg);
        assert!(
            destroyed.load(std::sync::atomic::Ordering::SeqCst),
            "destroy() must have been called by the time drop returns"
        );
        ManuallyDrop::into_inner(tmp);
    }

    /// An unmount must not fail merely because the filesystem is still in use. The
    /// Mount is consumed by the unmount attempt, so a caller that gets EBUSY has
    /// nothing left to retry with and the filesystem is left mounted (issue #686).
    #[test]
    fn umount_succeeds_while_filesystem_is_busy() {
        use std::time::SystemTime;

        use crate::FileAttr;
        use crate::FileHandle;
        use crate::FileType;
        use crate::INodeNo;
        use crate::ReplyAttr;

        /// Serves getattr, which is all that opening the mount root needs
        struct RootDirFs;
        impl Filesystem for RootDirFs {
            fn getattr(
                &self,
                _req: &Request,
                ino: INodeNo,
                _fh: Option<FileHandle>,
                reply: ReplyAttr,
            ) {
                let now = SystemTime::now();
                reply.attr(
                    &std::time::Duration::from_secs(1),
                    &FileAttr {
                        ino,
                        size: 0,
                        blocks: 0,
                        atime: now,
                        mtime: now,
                        ctime: now,
                        crtime: now,
                        kind: FileType::Directory,
                        perm: 0o755,
                        nlink: 2,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 4096,
                        flags: 0,
                    },
                );
            }
        }

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let mountpoint = tmp.path().canonicalize().unwrap();
        let mut session = Session::new(RootDirFs, &mountpoint, &Config::default()).unwrap();
        let mut unmounter = session.unmount_callable();
        let runner = std::thread::spawn(move || session.run());
        // The kernel forwards requests only after the init reply was processed, so a
        // completed operation proves the session loop is past the handshake
        let _ = std::fs::metadata(&mountpoint);

        // An open handle on the mount root makes an eager unmount fail with EBUSY
        let busy = std::fs::File::open(&mountpoint).unwrap();
        unmounter
            .unmount()
            .expect("unmount must not fail while the filesystem is in use");

        // Releasing the handle lets the lazily detached filesystem go away, ending
        // the session
        drop(busy);
        runner.join().unwrap().unwrap();
        ManuallyDrop::into_inner(tmp);
    }

    /// The fusectl abort file for the FUSE mount at `mountpoint`: the connection
    /// directory is named after the mount's anonymous device number.
    fn fusectl_abort_path(mountpoint: &Path) -> Option<std::path::PathBuf> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        let mut device = None;
        for line in mountinfo.lines() {
            let mut fields = line.split(' ');
            let (Some(dev), Some(path)) = (fields.nth(2), fields.nth(1)) else {
                continue;
            };
            // mountinfo octal-escapes special characters; the tempdir path has none.
            // Later entries are mounted on top of earlier ones, so the last match wins
            if Path::new(path) == mountpoint {
                let (major, minor) = dev.split_once(':')?;
                let (major, minor): (u64, u64) = (major.parse().ok()?, minor.parse().ok()?);
                // fusectl names the directory with the raw kernel-internal
                // device number, (major << 20) | minor: fuse_ctl_add_conn()
                // prints fc->dev (= sb->s_dev) without re-encoding it
                device = Some((major << 20) | minor);
            }
        }
        let path = std::path::PathBuf::from(format!("/sys/fs/fuse/connections/{}/abort", device?));
        path.exists().then_some(path)
    }
}
