//! Mounting: serve the share on a loopback port, then mount it with `mount_smbfs`

use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use super::client::Client;
use super::client::PendingInit;
use super::ntlm;
use super::server::Server;
use super::server::Stopper;
use super::smb2::Share;
use super::smb2::random;
use super::transport::Transport;
use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::MountOption;
use log::debug;
use log::error;
use log::info;
use log::warn;

/// The user SMB clients log on as. Its password is made up for each mount
const USER: &str = "fuser";
/// The share, unless `MountOption::FSName` names one
const DEFAULT_SHARE: &str = "fuser";
const MOUNT_SMBFS: &str = "/sbin/mount_smbfs";
/// How often to check whether the share was unmounted by someone else
const WATCH_INTERVAL: Duration = Duration::from_millis(500);
/// How long an unmount waits on requests the session does not answer before the
/// connection is ended, so that the unmount can finish
const STALL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `mount_smbfs` has not finished
    Mounting,
    Mounted,
    /// The mount was dropped before `mount_smbfs` finished
    Cancelled,
    /// Unmounted, or never mounted
    Gone,
}

#[derive(Debug)]
struct Shared {
    transport: Arc<Transport>,
    state: Mutex<State>,
    /// Canonical, as the mount table lists it
    mountpoint: PathBuf,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// What the mount options ask of the share and of `mount_smbfs`
#[derive(Debug)]
struct Settings {
    share: String,
    read_only: bool,
    /// For `mount_smbfs -o`
    mount_options: Vec<&'static str>,
}

impl Settings {
    fn new(options: &[MountOption]) -> Self {
        let mut settings = Settings {
            share: DEFAULT_SHARE.to_owned(),
            read_only: false,
            mount_options: Vec::new(),
        };
        for option in options {
            match option {
                MountOption::FSName(name) if is_share_name(name) => {
                    settings.share.clone_from(name);
                }
                MountOption::RO => {
                    settings.read_only = true;
                    settings.mount_options.push("rdonly");
                }
                MountOption::RW => settings.read_only = false,
                MountOption::NoExec => settings.mount_options.push("noexec"),
                MountOption::NoAtime => settings.mount_options.push("noatime"),
                MountOption::Sync => settings.mount_options.push("sync"),
                // smbfs mounts are always nosuid and nodev
                MountOption::NoSuid | MountOption::NoDev => {}
                MountOption::Exec | MountOption::Atime | MountOption::Async => {}
                other => warn!("the SMB mount backend ignores the mount option {other:?}"),
            }
        }
        settings
    }
}

/// Whether `name` makes a share name that needs no quoting anywhere
fn is_share_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn random_password() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    random(&mut bytes)?;
    Ok(bytes.iter().fold(String::new(), |mut hex, b| {
        hex.push_str(&format!("{b:02x}"));
        hex
    }))
}

fn io_error(errno: crate::Errno) -> io::Error {
    io::Error::from_raw_os_error(errno.code())
}

pub(crate) struct MountImpl {
    shared: Arc<Shared>,
    stopper: Stopper,
    server: Option<JoinHandle<()>>,
}

impl fmt::Debug for MountImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MountImpl")
            .field("shared", &self.shared)
            .finish_non_exhaustive()
    }
}

impl MountImpl {
    /// Start serving the share, and mount it on a thread of its own once the session has
    /// answered INIT. `mount_smbfs` does not return until the mount has made requests, and
    /// the session serves none until its loop runs, after this has returned.
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        // Requests carry the mounting user however the mount is shared: see Session::new
        let _ = acl;
        let settings = Settings::new(options);
        let mountpoint = std::fs::canonicalize(mountpoint)
            .map_err(|err| super::super::context(mountpoint.display(), err))?;

        let transport = Arc::new(Transport::new());
        // SAFETY: neither call has preconditions
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let client = Arc::new(Client::new(transport.clone(), uid, gid));
        let init = client.begin_init().map_err(io_error)?;

        let password = random_password()?;
        let mut guid = [0; 16];
        random(&mut guid)?;
        let server = Server::bind(Share {
            client: client.clone(),
            name: settings.share.clone(),
            read_only: settings.read_only,
            user: USER.to_owned(),
            nt_hash: ntlm::nt_hash(&password),
            guid,
        })?;
        let addr = server.addr()?;
        let stopper = server.stopper()?;
        let server = std::thread::Builder::new()
            .name("fuser-smb".to_owned())
            .spawn(move || server.run())?;
        debug!("serving share {} on {addr}", settings.share);

        let dev_fuse = Arc::new(DevFuse::from_transport(transport.clone())?);
        let shared = Arc::new(Shared {
            transport,
            state: Mutex::new(State::Mounting),
            mountpoint,
        });
        let mount = MountImpl {
            shared: shared.clone(),
            stopper,
            server: Some(server),
        };
        let url = format!(
            "//{USER}:{password}@{}:{}/{}",
            addr.ip(),
            addr.port(),
            settings.share
        );
        std::thread::Builder::new()
            .name("fuser-smb-mount".to_owned())
            .spawn(move || mount_and_watch(&shared, &client, init, &url, &settings))?;
        Ok((dev_fuse, mount))
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        let mut state = self.shared.state();
        match *state {
            State::Mounted => {
                unmount_while_serving(&self.shared)?;
                *state = State::Gone;
            }
            // Dropping this ends the connection, which fails what mount_smbfs is waiting for.
            // Should it mount all the same, the mount thread unmounts it
            State::Mounting => *state = State::Cancelled,
            State::Cancelled | State::Gone => {}
        }
        Ok(())
    }
}

impl Drop for MountImpl {
    fn drop(&mut self) {
        self.stopper.stop();
        // Ends the session loop, as an unmount ends a FUSE connection
        self.shared.transport.close();
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

/// Run on the mount thread: mount once INIT is answered, then end the connection if someone
/// else unmounts the share
fn mount_and_watch(
    shared: &Shared,
    client: &Client,
    init: PendingInit,
    url: &str,
    settings: &Settings,
) {
    if let Err(errno) = client.complete_init(init) {
        // Session::new reports what went wrong
        debug!("INIT failed ({errno:?}); not mounting");
        *shared.state() = State::Gone;
        return;
    }
    if *shared.state() != State::Mounting {
        return;
    }

    let mut command = Command::new(MOUNT_SMBFS);
    // Never prompt for a password
    command.arg("-N");
    if !settings.mount_options.is_empty() {
        command.arg("-o").arg(settings.mount_options.join(","));
    }
    command
        .arg(url)
        .arg(&shared.mountpoint)
        .stdin(Stdio::null());
    debug!(
        "{MOUNT_SMBFS} of share {} on {}",
        settings.share,
        shared.mountpoint.display()
    );
    let output = command.output();

    let mut state = shared.state();
    match output {
        Ok(output) if output.status.success() => {
            if *state == State::Cancelled {
                *state = State::Gone;
                drop(state);
                // Forced: the server may already be gone
                if let Err(err) = unmount(&shared.mountpoint, true) {
                    warn!("unmounting {}: {err}", shared.mountpoint.display());
                }
                return;
            }
            *state = State::Mounted;
            info!(
                "mounted share {} on {}",
                settings.share,
                shared.mountpoint.display()
            );
        }
        Ok(output) => {
            if *state != State::Cancelled {
                error!(
                    "{MOUNT_SMBFS} failed ({}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            *state = State::Gone;
            drop(state);
            // Nothing is mounted to end the session: end its connection instead
            shared.transport.close();
            return;
        }
        Err(err) => {
            error!("{MOUNT_SMBFS}: {err}");
            *state = State::Gone;
            drop(state);
            shared.transport.close();
            return;
        }
    }
    drop(state);

    loop {
        std::thread::sleep(WATCH_INTERVAL);
        let mut state = shared.state();
        if *state != State::Mounted {
            return;
        }
        if !is_mounted(&shared.mountpoint) {
            info!("{} was unmounted", shared.mountpoint.display());
            *state = State::Gone;
            drop(state);
            shared.transport.close();
            return;
        }
    }
}

fn unmount(mountpoint: &Path, force: bool) -> io::Result<()> {
    let path = CString::new(mountpoint.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in mount point"))?;
    if force {
        nix::mount::unmount(path.as_c_str(), nix::mount::MntFlags::MNT_FORCE)
    } else {
        super::super::libc_umount(&path)
    }
    .map_err(io::Error::from)
}

/// Unmount while the session answers what the unmount sends, such as the writes smbfs still
/// holds. If the session has stopped answering, end its connection, so that the requests
/// fail rather than hang the unmount.
fn unmount_while_serving(shared: &Shared) -> io::Result<()> {
    let (sender, result) = mpsc::channel();
    let mountpoint = shared.mountpoint.clone();
    std::thread::Builder::new()
        .name("fuser-smb-umount".to_owned())
        .spawn(move || {
            let _ = sender.send(unmount(&mountpoint, false));
        })?;
    loop {
        match result.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if shared.transport.stalled(STALL_TIMEOUT) {
                    warn!(
                        "the session is not answering requests: ending its connection to unmount"
                    );
                    shared.transport.close();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("unmount thread exited"));
            }
        }
    }
}

/// Whether an smbfs is mounted on `mountpoint`. Reads the mount table only, without a
/// request to the filesystem, which may be the one not answering.
fn is_mounted(mountpoint: &Path) -> bool {
    // SAFETY: a null buffer asks for the number of mounts
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    let Ok(count) = usize::try_from(count) else {
        // Cannot tell: assume it still is
        return true;
    };
    // Room for mounts made meanwhile
    // SAFETY: statfs is plain data, for which zeroes are valid
    let mut mounts = vec![unsafe { std::mem::zeroed::<libc::statfs>() }; count + 8];
    let size = (mounts.len() * size_of::<libc::statfs>()) as libc::c_int;
    // SAFETY: the buffer holds `size` bytes
    let count = unsafe { libc::getfsstat(mounts.as_mut_ptr(), size, libc::MNT_NOWAIT) };
    let Ok(count) = usize::try_from(count) else {
        return true;
    };
    mounts.truncate(count);
    mounts.iter().any(|mount| {
        // SAFETY: the kernel NUL-terminates both names
        let (on, fstype) = unsafe {
            (
                CStr::from_ptr(mount.f_mntonname.as_ptr()),
                CStr::from_ptr(mount.f_fstypename.as_ptr()),
            )
        };
        on.to_bytes() == mountpoint.as_os_str().as_bytes() && fstype.to_bytes() == b"smbfs"
    })
}
