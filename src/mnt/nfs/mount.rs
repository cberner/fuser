//! Mounting and unmounting through `mount_nfs`.

use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use log::debug;
use log::error;
use log::info;
use log::warn;
use parking_lot::Condvar;
use parking_lot::Mutex;

use super::fuse::Fuse;
use super::nfs3::Nfs;
use super::rpc::Server;
use super::rpc::Stopper;
use super::transport::Caller;
use super::transport::Transport;
use crate::MountOption;
use crate::SessionACL;
use crate::dev_fuse::DevFuse;

const MOUNT_NFS: &str = "/sbin/mount_nfs";
/// How often the mount table is checked for an unmount by someone else
const WATCH_INTERVAL: Duration = Duration::from_millis(100);
/// How long `Mount::new` waits to see whether `mount_nfs` fails before the session could
/// answer it
const EARLY_FAILURE_WAIT: Duration = Duration::from_secs(10);
/// How long `wait_mounted` waits for `mount_nfs` once the session runs
const MOUNT_WAIT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// `mount_nfs` is running
    Mounting,
    Mounted,
    /// Being unmounted by `umount_impl`
    Unmounting,
    /// `mount_nfs` failed
    Failed,
    Unmounted,
}

#[derive(Debug)]
struct State {
    phase: Phase,
    error: Option<String>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    fuse: Fuse,
    transport: Arc<Transport>,
    stopper: Stopper,
    /// Set by `umount_impl` while mounting, so that a mount which completes anyway is undone
    cancelled: AtomicBool,
    mountpoint: CString,
    source: String,
}

impl Shared {
    fn set_phase(&self, phase: Phase) {
        self.state.lock().phase = phase;
        self.changed.notify_all();
    }

    fn phase(&self) -> Phase {
        self.state.lock().phase
    }

    /// Ends the session and stops the server
    fn teardown(&self) {
        self.fuse.shutdown();
        self.stopper.stop();
    }
}

#[derive(Debug)]
pub(crate) struct MountImpl {
    shared: Arc<Shared>,
    server: Option<JoinHandle<()>>,
    watcher: Option<JoinHandle<()>>,
}

impl MountImpl {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        if acl != SessionACL::Owner {
            warn!(
                "The NFS backend cannot tell users apart: every request reaches the filesystem \
                 as the mounting user, whatever {acl:?} allows"
            );
        }
        // As the mount table names it, so that the watcher can find it there
        let canonical = std::fs::canonicalize(mountpoint).map_err(|err| {
            super::super::context(format_args!("mountpoint {}", mountpoint.display()), err)
        })?;
        let mountpoint_c = CString::new(canonical.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;

        let transport = Arc::new(Transport::default());
        let device = Arc::new(DevFuse::from_transport(transport.clone())?);
        let caller = Caller {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        };
        let export = super::export_name(options);
        let read_only = options.contains(&MountOption::RO);
        let fuse = Fuse::new(transport.clone(), caller);
        let server = Server::bind(Nfs::new(fuse.clone(), read_only, &export)?, 0)?;
        let port = server.port()?;
        let nfs_options = super::mount_nfs_options(options, port);
        let source = format!("127.0.0.1:/{export}");

        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                phase: Phase::Mounting,
                error: None,
            }),
            changed: Condvar::new(),
            fuse: fuse.clone(),
            transport: transport.clone(),
            stopper: server.stopper()?,
            cancelled: AtomicBool::new(false),
            mountpoint: mountpoint_c,
            source: source.clone(),
        });

        // FUSE_INIT goes first, for Session::new to answer
        let init = fuse.start_init().map_err(io::Error::from_raw_os_error)?;
        // Served from the start: mount_nfs's first calls are what this waits for below, before
        // the session runs to answer FUSE_INIT. Their FUSE requests queue behind FUSE_INIT
        std::thread::Builder::new()
            .name("fuser-nfs-init".to_string())
            .spawn(move || match fuse.finish_init(&init) {
                Ok(()) => fuse.release_idle_forever(),
                Err(errno) => error!("FUSE_INIT failed: {}", io::Error::from_raw_os_error(errno)),
            })?;
        let server = std::thread::Builder::new()
            .name("fuser-nfs-server".to_string())
            .spawn(move || server.run())?;

        let mut command = Command::new(MOUNT_NFS);
        command
            .arg("-o")
            .arg(nfs_options.join(","))
            .arg(&source)
            .arg(&canonical);
        debug!("Running {command:?}");
        let watcher = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("fuser-nfs-mount".to_string())
                .spawn(move || mount_and_watch(&shared, command))?
        };

        let mut mount = MountImpl {
            shared,
            server: Some(server),
            watcher: Some(watcher),
        };
        // mount_nfs cannot finish before the session runs, as the kernel's first calls need
        // the filesystem to answer. But most failures, such as a refused mount(2), come before
        // those calls, so wait for them and report them here
        let deadline = Instant::now() + EARLY_FAILURE_WAIT;
        while mount.shared.phase() == Phase::Mounting
            && transport.submitted() < 2
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        if mount.shared.phase() == Phase::Failed {
            let err = mount.error();
            let _ = mount.umount_impl();
            return Err(err);
        }
        Ok((device, mount))
    }

    fn error(&self) -> io::Error {
        io::Error::other(
            self.shared
                .state
                .lock()
                .error
                .clone()
                .unwrap_or_else(|| "mount_nfs failed".to_string()),
        )
    }

    /// Waits for `mount_nfs` to finish, which needs the session to run
    pub(crate) fn wait_mounted(&self) -> io::Result<()> {
        let deadline = Instant::now() + MOUNT_WAIT;
        let mut state = self.shared.state.lock();
        while state.phase == Phase::Mounting {
            if self
                .shared
                .changed
                .wait_until(&mut state, deadline)
                .timed_out()
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mount_nfs did not finish",
                ));
            }
        }
        if state.phase == Phase::Failed {
            drop(state);
            return Err(self.error());
        }
        Ok(())
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        let mut state = self.shared.state.lock();
        match state.phase {
            Phase::Mounting => {
                // The kernel's calls fail once the session has gone, which fails mount_nfs
                self.shared.cancelled.store(true, Ordering::SeqCst);
                drop(state);
                self.shared.teardown();
            }
            Phase::Mounted => {
                state.phase = Phase::Unmounting;
                drop(state);
                if let Err(err) = super::super::libc_umount(&self.shared.mountpoint) {
                    // Still mounted, and still served: the watcher ends the session once
                    // whoever holds it busy lets go and it is unmounted
                    self.shared.set_phase(Phase::Mounted);
                    return Err(io::Error::from(err));
                }
                self.shared.set_phase(Phase::Unmounted);
                self.shared.teardown();
            }
            Phase::Unmounting | Phase::Failed | Phase::Unmounted => {
                drop(state);
                self.shared.teardown();
            }
        }
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        Ok(())
    }
}

/// Runs `mount_nfs`, then watches for the filesystem to be unmounted by someone else
fn mount_and_watch(shared: &Shared, mut command: Command) {
    let failure = match run_mount_nfs(shared, &mut command) {
        Ok(()) => None,
        Err(failure) => Some(failure),
    };
    if let Some(failure) = failure {
        error!("{failure}");
        {
            let mut state = shared.state.lock();
            state.error = Some(failure);
            state.phase = Phase::Failed;
        }
        shared.changed.notify_all();
        // So that the session ends, with an error
        shared.transport.fail();
        shared.stopper.stop();
        return;
    }
    if shared.cancelled.load(Ordering::SeqCst) {
        // Unmounted before it was mounted: undo it. Nothing serves it any more
        let _ = nix::mount::unmount(
            shared.mountpoint.as_c_str(),
            nix::mount::MntFlags::MNT_FORCE,
        );
        shared.set_phase(Phase::Unmounted);
        return;
    }
    info!("Mounted {} on {:?}", shared.source, shared.mountpoint);
    shared.set_phase(Phase::Mounted);

    let mut state = shared.state.lock();
    loop {
        match state.phase {
            Phase::Mounted => {
                if !is_mounted(&shared.mountpoint, &shared.source) {
                    state.phase = Phase::Unmounted;
                    drop(state);
                    shared.changed.notify_all();
                    info!("{:?} was unmounted", shared.mountpoint);
                    shared.teardown();
                    return;
                }
            }
            Phase::Unmounting => {}
            Phase::Mounting | Phase::Failed | Phase::Unmounted => return,
        }
        shared.changed.wait_for(&mut state, WATCH_INTERVAL);
    }
}

/// Runs `mount_nfs`, killing it if the mount is cancelled meanwhile: its calls may otherwise
/// wait long for a server that has stopped
fn run_mount_nfs(shared: &Shared, command: &mut Command) -> Result<(), String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("running {MOUNT_NFS}: {err}"))?;
    let mut killed = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(err) => return Err(format!("waiting for {MOUNT_NFS}: {err}")),
        }
        if !killed && shared.cancelled.load(Ordering::SeqCst) {
            let _ = child.kill();
            killed = true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Err(format!("mount_nfs failed ({status}): {}", stderr.trim()))
}

/// Whether the mount table lists this NFS mount. Asks nothing of the mount itself, which could
/// block on the server
fn is_mounted(mountpoint: &CStr, source: &str) -> bool {
    // SAFETY: with a null buffer getfsstat only counts the mounts
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if count < 0 {
        // Assume it still is: unmounting what is gone is harmless, ending a live session not
        return true;
    }
    // Room for mounts made meanwhile
    let mut buf: Vec<libc::statfs> = Vec::with_capacity(count as usize + 16);
    let size = (buf.capacity() * size_of::<libc::statfs>()) as libc::c_int;
    // SAFETY: the buffer has room for `size` bytes, and getfsstat writes at most that
    let count = unsafe { libc::getfsstat(buf.as_mut_ptr(), size, libc::MNT_NOWAIT) };
    if count < 0 {
        return true;
    }
    // SAFETY: getfsstat initialized this many entries
    unsafe { buf.set_len(count as usize) };
    buf.iter().any(|fs| {
        // SAFETY: the kernel NUL-terminates these names
        let name = |field: &[libc::c_char]| unsafe { CStr::from_ptr(field.as_ptr()) };
        name(&fs.f_fstypename[..]) == c"nfs"
            && name(&fs.f_mntonname[..]) == mountpoint
            && name(&fs.f_mntfromname[..]).to_bytes() == source.as_bytes()
    })
}
