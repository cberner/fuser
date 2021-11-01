//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::{error, info, warn};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use zerocopy::FromBytes;

use crate::ll::{fuse_abi as abi, AlignedBox};
use crate::request::Request;
use crate::MountOption;
use crate::{
    channel::Channel,
    ll::{self, Request as _},
    mnt::Mount,
    reply::ReplySender,
};
use crate::{Filesystem, KernelConfig};

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to MAX_WRITE_SIZE bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub(crate) enum SessionACL {
    All,
    RootAndOwner,
    Owner,
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations
    pub(crate) filesystem: FS,
    /// Communication channel to the kernel driver
    ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: Option<Mount>,
    /// Mount point
    mountpoint: PathBuf,
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

fn inner_mount(
    mountpoint: &Path,
    options: &[MountOption],
) -> io::Result<(Channel, Mount, SessionACL)> {
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

    let ch = Channel::new(file);
    let allowed = if options.contains(&MountOption::AllowRoot) {
        SessionACL::RootAndOwner
    } else if options.contains(&MountOption::AllowOther) {
        SessionACL::All
    } else {
        SessionACL::Owner
    };
    Ok((ch, mount, allowed))
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    pub fn new(
        filesystem: FS,
        mountpoint: &Path,
        options: &[MountOption],
    ) -> io::Result<Session<FS>> {
        let (ch, mount, allowed) = inner_mount(mountpoint, options)?;
        Ok(Session {
            filesystem,
            ch,
            mount: Some(mount),
            mountpoint: mountpoint.to_owned(),
            allowed,
            session_owner: geteuid(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
        })
    }

    /// Return path of the mounted filesystem
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    pub fn run(&mut self) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buf = AlignedBox::new(BUFFER_SIZE);
        loop {
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive(buf.as_mut()) {
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

    /// Unmount the filesystem
    pub fn unmount(&mut self) {
        drop(std::mem::take(&mut self.mount));
    }
}

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
        info!("Unmounted {}", self.mountpoint().display());
    }
}

pub fn mount3(mountpoint: &Path, options: &[MountOption]) -> io::Result<(ChannelUninit, Mount)> {
    let (channel, mount, allowed) = inner_mount(mountpoint, options)?;
    let mut buffer = vec![0; 8192];
    let size = channel.receive(&mut buffer).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("mount3: Error receiving INIT message: {}", e),
        )
    })?;
    buffer.resize(size, 0);
    let init_msg =
        <abi::fuse_init_in_msg as FromBytes>::read_from_prefix(&*buffer).ok_or_else(|| {
            std::io::Error::new(
                io::ErrorKind::InvalidData,
                "mount3: Invalid INIT message size received from kernel",
            )
        })?;
    let init = ll::request::op::Init {
        header: &init_msg.header,
        arg: &init_msg.body,
    };

    let v = init.version();
    if v < ll::Version(7, 6) {
        error!("Unsupported FUSE ABI version {}", v);
        return Err(io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "Unsupported FUSE ABI version {}.  The fuser library requires at least v7.6",
                v
            ),
        ));
    }
    let kernel_config = KernelConfig::new(init.capabilities(), init.max_readahead());
    Ok((
        ChannelUninit {
            channel,
            init_msg,
            kernel_config,
            allowed,
        },
        mount,
    ))
}

/// A communication channel with the kernel that has not yet completed version
/// and capability negotiation with the kernel.  You can customise according to
/// your filesystem's requirements before calling `.init()`, much like with the
/// builder pattern.
#[derive(Debug)]
pub struct ChannelUninit {
    channel: Channel,
    init_msg: abi::fuse_init_in_msg,
    kernel_config: KernelConfig,
    allowed: SessionACL,
}

impl ChannelUninit {
    /// Get (and allow modification of) the config from the kernel.
    pub fn kconfig(&mut self) -> &mut KernelConfig {
        &mut self.kernel_config
    }
    /// Initialise this channel by sending a reply to the kernel's INIT request.
    pub fn init(self) -> io::Result<ChannelInit> {
        let msg = ll::request::op::Init {
            header: &self.init_msg.header,
            arg: &self.init_msg.body,
        };
        let resp = msg.reply(&self.kernel_config);
        let sender = self.channel.sender();
        resp.with_iovec(msg.unique(), |iov| sender.send(iov))?;
        Ok(ChannelInit {
            channel: self.channel,
            kernel_config: self.kernel_config,
            init_msg: self.init_msg,
            allowed: self.allowed,
        })
    }
}

/// Represents a communication channel with the kernel (/dev/fuse device) that
/// has been initialised.
#[derive(Debug)]
pub struct ChannelInit {
    channel: Channel,
    kernel_config: KernelConfig,
    init_msg: abi::fuse_init_in_msg,
    allowed: SessionACL,
}

/// Blocks reading from the kernel and dispatching reqests to your filesystem
/// implementation until there is an error.  A single request is handled at
/// any one time.
pub fn serve_fs_sync_forever<FS: Filesystem>(
    chan: &ChannelInit,
    filesystem: FS,
) -> std::io::Result<()> {
    let mut session = Session::<FS> {
        filesystem,
        ch: chan.channel.clone(),
        mount: None,
        mountpoint: PathBuf::new(),
        allowed: chan.allowed,
        session_owner: geteuid(),
        proto_major: chan.init_msg.body.major,
        proto_minor: chan.init_msg.body.minor,
        initialized: true,
        destroyed: false,
    };
    session.run()
}

#[cfg(feature = "mt")]
pub use multithread::serve_fs_mt_forever;

#[cfg(feature = "mt")]
mod multithread {
    use super::*;
    use ll::request::OwnedRequest;
    use rayon::iter::{ParallelBridge, ParallelIterator};

    struct RequestIterator {
        chan: ChannelInit,
        err: Option<io::Error>,

        // This channel is used as a bufferpool.  When we need a buffer we pull
        // one from here, and when we're done with a buffer we push it to
        // `pool_s`.  The channel has a capacity of 1 to limit the number of
        // idle buffers, thus limiting the total memory use.
        pool_take: crossbeam_channel::Receiver<ll::AlignedBox>,
        pool_put: crossbeam_channel::Sender<ll::AlignedBox>,
    }

    impl Iterator for RequestIterator {
        type Item = OwnedRequest;

        fn next(&mut self) -> Option<Self::Item> {
            if self.err.is_some() {
                // Stop on first error
                return None;
            }
            let mut buf = self
                .pool_take
                .try_recv()
                .unwrap_or_else(|_| AlignedBox::new(BUFFER_SIZE));
            loop {
                // Read the next request from the given channel to kernel driver
                // The kernel driver makes sure that we get exactly one request per read
                match self.chan.channel.receive(buf.as_mut()) {
                    Ok(size) => {
                        let req = OwnedRequest::from_boxed(buf);
                        let req = match req {
                            Ok((req, buf)) => {
                                if let Some(buf) = buf {
                                    // Requeue our buffer in the bufferpool
                                    let _ = self.pool_put.try_send(buf);
                                }
                                req
                            }
                            Err(_) => todo!(),
                        };
                        return Some(req);
                    }
                    Err(err) => match err.raw_os_error() {
                        // Operation interrupted. Accordingly to FUSE, this is safe to retry
                        Some(ENOENT) => continue,
                        // Interrupted system call, retry
                        Some(EINTR) => continue,
                        // Explicitly try again
                        Some(EAGAIN) => continue,
                        // Unhandled error
                        _ => {
                            self.err = Some(err);
                            return None;
                        }
                    },
                }
            }
        }
    }

    /// Blocks reading from the kernel and dispatching reqests to your filesystem
    /// implementation until there is an error.  Requests will be handled on a thread
    /// pool.  Instead of providing a Filesystem implementation you must provide a
    /// factory function for creating Filesystem implementations.  This will be called
    /// once for each thread that is started.
    pub fn serve_fs_mt_forever<FS: Filesystem>(
        chan: ChannelInit,
        factory: impl Fn() -> FS + Sync + Send,
    ) -> Result<(), io::Error> {
        let (pool_put, pool_take) = crossbeam_channel::bounded(1);
        let channel = chan.channel.clone();
        let ch_sender = channel.sender();
        let (proto_major, proto_minor) = (chan.init_msg.body.major, chan.init_msg.body.minor);
        let it = RequestIterator {
            chan: chan,
            err: None,
            pool_put: pool_put.clone(),
            pool_take: pool_take.clone(),
        };
        it.par_bridge().for_each_init(
            move || Session::<FS> {
                filesystem: factory(),
                ch: channel.clone(),
                mount: None,
                mountpoint: PathBuf::new(),
                // TODO: What is allowed?
                allowed: SessionACL::All,
                session_owner: geteuid(),
                proto_major,
                proto_minor,
                initialized: true,
                destroyed: false,
            },
            move |session, request| {
                let rreq = Request::from_owned_request(ch_sender.clone(), &request);
                rreq.dispatch(session);
                if let Some(b) = request.into_box() {
                    // We're done with it, so put it back in the buffer-pool
                    let _ = pool_put.try_send(b);
                }
            },
        );

        // TODO: Return the error that caused iteration to stop
        Ok(())
    }
}

/// The background session data structure
pub struct BackgroundSession {
    /// Path of the mounted filesystem
    pub mountpoint: PathBuf,
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Ensures the filesystem is unmounted when the session ends
    _mount: Mount,
}

impl BackgroundSession {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn new<FS: Filesystem + Send + 'static>(
        mut se: Session<FS>,
    ) -> io::Result<BackgroundSession> {
        let mountpoint = se.mountpoint().to_path_buf();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut se.mount);
        let mount = mount.ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;
        let guard = thread::spawn(move || {
            let mut se = se;
            se.run()
        });
        Ok(BackgroundSession {
            mountpoint,
            guard,
            _mount: mount,
        })
    }
    /// Unmount the filesystem and join the background thread.
    pub fn join(self) {
        let Self {
            mountpoint: _,
            guard,
            _mount,
        } = self;
        drop(_mount);
        guard.join().unwrap().unwrap();
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl<'a> fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "BackgroundSession {{ mountpoint: {:?}, guard: JoinGuard<()> }}",
            self.mountpoint
        )
    }
}

fn geteuid() -> libc::uid_t {
    // SAFETY: Nothing exciting here, it's just that all the functions in the
    // libc crate are unsafe.  `man geteuid` says: "Errors: These functions are
    // always successful."
    unsafe { libc::geteuid() }
}