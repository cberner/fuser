//! Native FFI bindings to libfuse.
//!
//! This is a small set of bindings that are required to mount/unmount FUSE filesystems and
//! open/close a fd to the FUSE kernel driver.

use std::env;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::io::IoSliceMut;
use std::io::Read;
use std::mem;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::ptr;
use std::sync::Arc;

use log::debug;
use nix::fcntl::FcntlArg;
use nix::fcntl::FdFlag;
use nix::fcntl::OFlag;
use nix::fcntl::fcntl;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockaddrStorage;
use nix::sys::socket::recvmsg;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::mount_options::MountOption;
use crate::mnt::mount_options::MountOptionGroup;
use crate::mnt::mount_options::option_group;
use crate::mnt::mount_options::option_to_escaped_string;
use crate::mnt::mount_options::option_to_flag;
use crate::mnt::mount_options::option_to_string;

const FUSERMOUNT_BIN: &str = "fusermount";
const FUSERMOUNT3_BIN: &str = "fusermount3";
const FUSERMOUNT_COMM_ENV: &str = "_FUSE_COMMFD";
const MOUNT_FUSEFS_BIN: &str = "mount_fusefs";

#[derive(Debug)]
pub(crate) struct MountImpl {
    mountpoint: CString,
    auto_unmount_socket: Option<UnixStream>,
}
impl MountImpl {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let mountpoint = mountpoint
            .canonicalize()
            .map_err(|err| crate::mnt::context(format_args!("{}", mountpoint.display()), err))?;
        let (file, sock) = fuse_mount_pure(mountpoint.as_os_str(), options, acl)?;
        let file = Arc::new(file);
        Ok((
            file,
            MountImpl {
                mountpoint: CString::new(mountpoint.as_os_str().as_bytes())?,
                auto_unmount_socket: sock,
            },
        ))
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        // The auto_unmount watcher only reacts once this process lets go of the mount, so
        // leaving the unmount to it keeps the mountpoint occupied for the rest of the
        // process's life. Unmount here, as libfuse does, and close the socket afterwards
        // so the watcher exits without a mount left to clean up (issue #407)
        let result = self.umount_now();
        drop(mem::take(&mut self.auto_unmount_socket));
        result
    }

    fn umount_now(&self) -> io::Result<()> {
        if let Err(err) = crate::mnt::libc_umount(&self.mountpoint) {
            if err == nix::errno::Errno::EPERM {
                // Linux always returns EPERM for non-root users.  We have to let the
                // library go through the setuid-root "fusermount -u" to unmount.
                fuse_unmount_pure(&self.mountpoint)?;
                return Ok(());
            } else {
                return Err(err.into());
            }
        }
        Ok(())
    }
}

fn fuse_mount_pure(
    mountpoint: &OsStr,
    options: &[MountOption],
    acl: SessionACL,
) -> Result<(DevFuse, Option<UnixStream>), io::Error> {
    if options.contains(&MountOption::AutoUnmount) {
        return fuse_mount_auto_unmount(mountpoint, options, acl);
    }

    // The direct mount path is currently implemented only for Linux and macOS.
    // Other supported Unix targets (such as the BSDs) rely on the setuid
    // mount helper, which mirrors libfuse's approach.
    if cfg!(any(target_os = "linux", target_os = "android")) || cfg!(target_os = "macos") {
        let res = fuse_mount_sys(mountpoint, options, acl)?;
        match res {
            Some(file) => return Ok((file, None)),
            None => {
                // Retry
            }
        }
    }

    fuse_mount_fusermount(&detect_fusermount_bin()?, mountpoint, options, acl)
}

/// `auto_unmount` needs something that outlives this process to do the unmount, which is
/// normally the fusermount helper: it keeps running holding the other end of a socket, and
/// unmounts once this process has let go of it. Systems that ship no FUSE userspace at all
/// have no such helper (issue #283), so where this process may mount by itself, keep that
/// watch here instead.
fn fuse_mount_auto_unmount(
    mountpoint: &OsStr,
    options: &[MountOption],
    acl: SessionACL,
) -> Result<(DevFuse, Option<UnixStream>), Error> {
    // Naming the option matters: mounting without it may well work, and nothing else
    // says that the helper was needed only because auto_unmount asked for it
    let no_helper = match detect_fusermount_bin() {
        Ok(fusermount_bin) => {
            return fuse_mount_fusermount(&fusermount_bin, mountpoint, options, acl)
                .map_err(|err| crate::mnt::context("mounting with auto_unmount", err));
        }
        Err(err) => err,
    };

    // Unmounting takes the same privilege as mounting by hand does, so wherever this
    // succeeds the watcher can finish the job
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (watcher_socket, session_socket) = UnixStream::pair()?;
        // Fork before the FUSE device is opened, so that the watcher never holds it: a
        // live device descriptor keeps the connection alive after this process is gone,
        // leaving every access to the mountpoint blocked rather than failing
        spawn_unmount_watcher(mountpoint, &watcher_socket, &session_socket)?;
        if let Some(file) = fuse_mount_sys(mountpoint, options, acl)? {
            return Ok((file, Some(session_socket)));
        }
        // Unprivileged, so dropping the socket ends the watcher, which then finds the
        // mountpoint unmounted and leaves it alone
    }

    Err(crate::mnt::context(
        "mounting with auto_unmount, which needs either a FUSE mount helper or the \
         privilege to mount directly",
        no_helper,
    ))
}

/// Fork a watcher that unmounts `mountpoint` once `socket` reaches EOF, which is once
/// every copy of the session's end is closed - including by this process dying, which is
/// what `auto_unmount` is for.
///
/// Unlike the setuid fusermount helper, the watcher keeps this process's credentials, so
/// it can always tell an unserved mount of its own from one it may not look at. That
/// distinction is what fusermount needs `allow_other` for.
///
/// Forks twice, so that the watcher is init's child rather than this process's: nothing
/// here would ever reap it, and a caller reaping its own children must not find one it
/// never started.
///
/// The watcher reports itself over a pipe rather than through an exit status, because a
/// caller that reaps its own children takes that status first and leaves nothing to read.
/// A mount whose watcher silently failed to start is one that outlives the process that
/// asked for it to be unmounted, so this has to be known rather than assumed.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn spawn_unmount_watcher(
    mountpoint: &OsStr,
    socket: &UnixStream,
    session_socket: &UnixStream,
) -> io::Result<()> {
    // Everything the watcher touches has to be ready before the fork, because only
    // async-signal-safe work is allowed afterwards, and that rules out allocating
    let mountpoint = CString::new(mountpoint.as_bytes())?;
    let socket_fd = socket.as_raw_fd();
    // The watcher inherits this end too, and holding the only other writer would keep it
    // from ever reaching EOF, so it closes this before anything else
    let session_fd = session_socket.as_raw_fd();
    let (started_read, started_write) = nix::unistd::pipe2(OFlag::O_CLOEXEC)?;
    let started_write_fd = started_write.as_raw_fd();

    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Child => match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Child) => {
                unmount_watcher(&mountpoint, socket_fd, session_fd, started_write_fd)
            }
            // Whether or not there is a watcher, this exit closes the copy of the pipe
            // that came with the fork, and orphans any watcher onto init
            Ok(nix::unistd::ForkResult::Parent { .. }) | Err(_) => unsafe { libc::_exit(0) },
        },
        nix::unistd::ForkResult::Parent { child } => {
            // Leaves the watcher as the only writer, so that the read below ends either
            // with its byte or, if there is no watcher, with end of file
            drop(started_write);
            // The intermediate exits as soon as it has forked. Its status says nothing
            // reliable, but it still has to be reaped by someone, and a caller reaping
            // children of its own may have taken it already
            while let Err(nix::errno::Errno::EINTR) = nix::sys::wait::waitpid(child, None) {}

            // A signal handler the caller installed without SA_RESTART interrupts this
            // read, which says nothing about whether there is a watcher
            let mut started = [0u8; 1];
            let started = loop {
                match nix::unistd::read(&started_read, &mut started) {
                    Ok(read) => break read == 1,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => break false,
                }
            };
            if started {
                Ok(())
            } else {
                Err(Error::other(
                    "auto_unmount: failed to fork a watcher to unmount the filesystem",
                ))
            }
        }
    }
}

/// Close everything the watcher inherited except `keep` and stdio.
///
/// This is not tidiness: the watcher outlives the process it was forked from, so a FUSE
/// device it holds for some other mount of that process keeps that mount's connection
/// alive with nothing left to serve it, and every access to it blocks rather than
/// failing. `close_range()` does it in one call, but it needs Linux 5.9, which the
/// systems without a mount helper are the least likely to have, so fall back to closing
/// them one at a time as libfuse does.
///
/// Runs in a forked child: async-signal-safe calls only.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn close_inherited_fds(keep: RawFd) {
    /// Bounds the fallback when the descriptor limit is unset or absurd. Well above any
    /// real one, and the sweep only ever runs once
    const MAX_SWEPT_FD: RawFd = 1 << 20;

    unsafe {
        let above = libc::syscall(
            libc::SYS_close_range,
            keep as libc::c_uint + 1,
            libc::c_uint::MAX,
            0,
        ) == 0;
        let below = keep <= libc::STDERR_FILENO + 1
            || libc::syscall(
                libc::SYS_close_range,
                libc::STDERR_FILENO as libc::c_uint + 1,
                keep as libc::c_uint - 1,
                0,
            ) == 0;
        if above && below {
            return;
        }

        // rlim_cur is not the same width on every target, and may be RLIM_INFINITY
        let mut limit: libc::rlimit = mem::zeroed();
        let last = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            RawFd::try_from(limit.rlim_cur).unwrap_or(MAX_SWEPT_FD)
        } else {
            MAX_SWEPT_FD
        }
        .min(MAX_SWEPT_FD);
        for fd in (libc::STDERR_FILENO + 1)..last {
            if fd != keep {
                libc::close(fd);
            }
        }
    }
}

/// Runs in a forked child, so every call it makes must be async-signal-safe: no
/// allocation, and no way to report an error even if one occurs.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unmount_watcher(mountpoint: &CStr, socket_fd: RawFd, session_fd: RawFd, started_fd: RawFd) -> ! {
    unsafe {
        // Holding the session's end here would keep the read below from ever reaching
        // EOF. The sweep further down would close it too, but it is bounded by a
        // descriptor limit that this one descriptor must not depend on
        libc::close(session_fd);

        // Leave the caller's session and block its signals, so that a Ctrl-C on its
        // terminal cannot kill the watcher before it has done its job. Blocking them
        // first also keeps the handshake below from being interrupted
        libc::setsid();
        let mut signals: libc::sigset_t = mem::zeroed();
        libc::sigfillset(&mut signals);
        libc::sigprocmask(libc::SIG_BLOCK, &signals, ptr::null_mut());

        // Reaching this at all is what the caller is waiting to hear: everything from
        // here on either cannot fail or does not decide whether there is a watcher. The
        // sweep below closes the pipe, which is all that is left to do with it
        libc::write(started_fd, [1u8].as_ptr().cast(), 1);

        close_inherited_fds(socket_fd);

        let mut buf = [0u8; 16];
        loop {
            let read = libc::read(socket_fd, buf.as_mut_ptr().cast(), buf.len());
            if read == 0 || (read < 0 && nix::errno::Errno::last() != nix::errno::Errno::EINTR) {
                break;
            }
        }

        // Unmount only a mountpoint that is still this filesystem and no longer served,
        // which is exactly when opening it fails with ENOTCONN. A successful open means
        // it was unmounted already, or that something else has taken the path since, and
        // unmounting would then take out the wrong filesystem
        let fd = libc::open(mountpoint.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            libc::close(fd);
        } else if nix::errno::Errno::last() == nix::errno::Errno::ENOTCONN {
            libc::umount2(mountpoint.as_ptr(), libc::MNT_DETACH);
        }
        libc::_exit(0)
    }
}

/// Only reached once `libc_umount()` has failed with EPERM, i.e. unprivileged, so
/// there is no point in retrying the same unmount syscall with different flags
fn fuse_unmount_pure(mountpoint: &CStr) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if nix::mount::unmount(mountpoint, nix::mount::MntFlags::MNT_FORCE).is_ok() {
            return Ok(());
        }
    }
    crate::mnt::fusermount_unmount(&detect_fusermount_bin()?, mountpoint)
}

fn detect_fusermount_bin() -> io::Result<String> {
    if let Some(fusermount) = env::var_os("FUSERMOUNT_PATH") {
        return Ok(fusermount
            .to_str()
            .expect("FUSERMOUNT_PATH is not UTF-8")
            .to_owned());
    }

    let candidates = [
        FUSERMOUNT3_BIN.to_string(),
        FUSERMOUNT_BIN.to_string(),
        MOUNT_FUSEFS_BIN.to_string(),
        format!("/sbin/{FUSERMOUNT3_BIN}"),
        format!("/sbin/{FUSERMOUNT_BIN}"),
        format!("/sbin/{MOUNT_FUSEFS_BIN}"),
        format!("/bin/{FUSERMOUNT3_BIN}"),
        format!("/bin/{FUSERMOUNT_BIN}"),
    ];
    for name in candidates.iter() {
        if Command::new(name).arg("-h").output().is_ok() {
            return Ok(name.to_string());
        }
    }
    // None of these could be started, so naming a single guessed default would be misleading
    Err(Error::new(
        ErrorKind::NotFound,
        format!(
            "no FUSE mount helper found, tried {} (set FUSERMOUNT_PATH to override)",
            candidates.join(", ")
        ),
    ))
}

fn receive_fusermount_message(socket: &UnixStream) -> Result<DevFuse, Error> {
    let mut io_vec_buf = [0u8];
    let mut iov = [IoSliceMut::new(&mut io_vec_buf)];
    let mut cmsg_buffer = nix::cmsg_space!(RawFd);

    let msg = loop {
        match recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buffer),
            MsgFlags::empty(),
        ) {
            Ok(msg) => break msg,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };

    if msg.bytes == 0 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Unexpected EOF reading from fusermount",
        ));
    }

    for cmsg in msg
        .cmsgs()
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?
    {
        match cmsg {
            ControlMessageOwned::ScmRights(fds) => {
                if let Some(&fd) = fds.first() {
                    if fd < 0 {
                        return Err(ErrorKind::InvalidData.into());
                    }
                    return Ok(DevFuse(unsafe { File::from_raw_fd(fd) }));
                }
            }
            other => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Unknown control message from fusermount: {:?}", other),
                ));
            }
        }
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "No SCM_RIGHTS message received from fusermount",
    ))
}

/// Clear `FD_CLOEXEC` after fork before exec.
/// This is needed to pass the file descriptor to a child process without risking descriptor leak.
unsafe fn clear_cloexec_in_pre_exec(command: &mut Command, fd: BorrowedFd<'_>) {
    let fd = fd.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            let fd = BorrowedFd::borrow_raw(fd);
            let current_flags = fcntl(fd, FcntlArg::F_GETFD)?;
            let current_flags = FdFlag::from_bits_retain(current_flags);
            if current_flags.contains(FdFlag::FD_CLOEXEC) {
                let cleared = current_flags & !FdFlag::FD_CLOEXEC;
                fcntl(fd, FcntlArg::F_SETFD(cleared))?;
            }
            Ok(())
        })
    };
}

fn fuse_mount_fusermount(
    fusermount_bin: &str,
    mountpoint: &OsStr,
    options: &[MountOption],
    acl: SessionACL,
) -> Result<(DevFuse, Option<UnixStream>), Error> {
    if fusermount_bin.ends_with(MOUNT_FUSEFS_BIN) {
        return fuse_mount_mount_fusefs(fusermount_bin, mountpoint, options, acl);
    }

    let (child_socket, receive_socket) = UnixStream::pair()?;

    let mut builder = Command::new(fusermount_bin);
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut options_strs: Vec<String> = options.iter().map(option_to_escaped_string).collect();
    options_strs.extend(acl.to_mount_option().map(|s| s.to_owned()));
    if !options_strs.is_empty() {
        builder.arg("-o");
        builder.arg(options_strs.join(","));
    }
    builder
        .arg("--")
        .arg(mountpoint)
        .env(FUSERMOUNT_COMM_ENV, child_socket.as_raw_fd().to_string());

    unsafe {
        clear_cloexec_in_pre_exec(&mut builder, child_socket.as_fd());
    }

    let fusermount_child = builder
        .spawn()
        .map_err(|err| crate::mnt::context(format_args!("spawning {fusermount_bin}"), err))?;

    drop(child_socket); // close socket in parent

    let file = match receive_fusermount_message(&receive_socket) {
        Ok(f) => f,
        Err(_) => {
            // Drop receive socket, since fusermount has exited with an error
            drop(receive_socket);
            let output = fusermount_child.wait_with_output().unwrap();
            let stderr_string = String::from_utf8_lossy(&output.stderr).to_string();
            return if stderr_string.contains("only allowed if 'user_allow_other' is set") {
                Err(io::Error::new(ErrorKind::PermissionDenied, stderr_string))
            } else {
                Err(io::Error::new(ErrorKind::Other, stderr_string))
            };
        }
    };
    let mut receive_socket = Some(receive_socket);

    if !options.contains(&MountOption::AutoUnmount) {
        // Only close the socket, if auto unmount is not set.
        // fusermount will keep running until the socket is closed, if auto unmount is set
        drop(mem::take(&mut receive_socket));
        let output = fusermount_child.wait_with_output()?;
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stdout));
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stderr));
    } else {
        if let Some(mut stdout) = fusermount_child.stdout {
            // TODO: do not ignore error.
            if let Ok(flags) = fcntl(&stdout, FcntlArg::F_GETFL) {
                let new_flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
                let _ = fcntl(&stdout, FcntlArg::F_SETFL(new_flags));
            }
            let mut buf = vec![0; 64 * 1024];
            if let Ok(len) = stdout.read(&mut buf) {
                debug!("fusermount: {}", String::from_utf8_lossy(&buf[..len]));
            }
        }
        if let Some(mut stderr) = fusermount_child.stderr {
            // TODO: do not ignore error.
            if let Ok(flags) = fcntl(&stderr, FcntlArg::F_GETFL) {
                let new_flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
                let _ = fcntl(&stderr, FcntlArg::F_SETFL(new_flags));
            }
            let mut buf = vec![0; 64 * 1024];
            if let Ok(len) = stderr.read(&mut buf) {
                debug!("fusermount: {}", String::from_utf8_lossy(&buf[..len]));
            }
        }
    }

    // TODO: do not ignore error.
    let _ = fcntl(&file, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));

    Ok((file, receive_socket))
}

fn fuse_mount_mount_fusefs(
    fusermount_bin: &str,
    mountpoint: &OsStr,
    options: &[MountOption],
    acl: SessionACL,
) -> Result<(DevFuse, Option<UnixStream>), Error> {
    let fuse_device = DevFuse::open()?;

    let fuse_fd = fuse_device.as_raw_fd();

    let mut builder = Command::new(fusermount_bin);
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    // Unlike fusermount, mount_fusefs decodes no escapes. That is why the platforms
    // using it reject comma and backslash in option values outright
    let mut options_strs: Vec<String> = options.iter().map(option_to_string).collect();
    options_strs.extend(acl.to_mount_option().map(|s| s.to_owned()));
    if !options_strs.is_empty() {
        builder.arg("-o");
        builder.arg(options_strs.join(","));
    }

    builder.arg(fuse_fd.to_string()).arg(mountpoint);

    unsafe { clear_cloexec_in_pre_exec(&mut builder, fuse_device.as_fd()) };

    let output = builder
        .output()
        .map_err(|err| crate::mnt::context(format_args!("running {fusermount_bin}"), err))?;
    if !output.status.success() {
        return Err(io::Error::new(
            ErrorKind::Other,
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok((fuse_device, None))
}

// If returned option is none. Then fusermount binary should be tried
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn fuse_mount_sys(
    mountpoint: &OsStr,
    options: &[MountOption],
    acl: SessionACL,
) -> Result<Option<DevFuse>, Error> {
    use std::os::unix::fs::PermissionsExt;

    let mountpoint_mode = File::open(mountpoint)
        .map_err(|err| crate::mnt::context(Path::new(mountpoint).display(), err))?
        .metadata()?
        .permissions()
        .mode();

    let file = DevFuse::open()?;
    assert!(
        file.as_raw_fd() > 2,
        "Conflict with stdin/stdout/stderr. fd={}",
        file.as_raw_fd()
    );

    let mut mount_options = format!(
        "fd={},rootmode={:o},user_id={},group_id={}",
        file.as_raw_fd(),
        mountpoint_mode,
        nix::unistd::getuid(),
        nix::unistd::getgid()
    );

    for option in options
        .iter()
        .filter(|x| option_group(x) == MountOptionGroup::KernelOption)
    {
        mount_options.push(',');
        mount_options.push_str(&option_to_string(option));
    }
    if let Some(acl_option) = acl.to_mount_option() {
        mount_options.push(',');
        mount_options.push_str(acl_option);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let mut flags = nix::mount::MsFlags::empty();
    #[cfg(target_os = "macos")]
    let mut flags = nix::mount::MntFlags::empty();

    if !options.contains(&MountOption::Dev) {
        // Default to nodev
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            flags |= nix::mount::MsFlags::MS_NODEV;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= nix::mount::MntFlags::MNT_NODEV;
        }
    }
    if !options.contains(&MountOption::Suid) {
        // Default to nosuid
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            flags |= nix::mount::MsFlags::MS_NOSUID;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= nix::mount::MntFlags::MNT_NOSUID;
        }
    }
    for flag in options
        .iter()
        .filter(|x| option_group(x) == MountOptionGroup::KernelFlag)
    {
        flags |= option_to_flag(flag)?;
    }

    // Default name is "/dev/fuse", then use the subtype, and lastly prefer the name
    let mut source = DevFuse::PATH;
    if let Some(MountOption::Subtype(subtype)) = options
        .iter()
        .find(|x| matches!(**x, MountOption::Subtype(_)))
    {
        source = subtype;
    }
    if let Some(MountOption::FSName(name)) = options
        .iter()
        .find(|x| matches!(**x, MountOption::FSName(_)))
    {
        source = name;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = nix::mount::mount(
        Some(source),
        mountpoint,
        Some("fuse"),
        flags,
        Some(mount_options.as_str()),
    );
    #[cfg(target_os = "macos")]
    let result = nix::mount::mount(source, mountpoint, flags, Some(mount_options.as_str()));

    match result {
        Ok(()) => Ok(Some(file)),
        Err(nix::errno::Errno::EPERM) => Ok(None), // Retry with fusermount
        Err(e) => Err(Error::new(
            ErrorKind::Other,
            format!(
                "Error calling mount() at {mountpoint:?} with {mount_options:?} and flags={flags:?}: {e}"
            ),
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn fuse_mount_sys(
    _mountpoint: &OsStr,
    _options: &[MountOption],
    _acl: SessionACL,
) -> Result<Option<DevFuse>, Error> {
    Ok(None)
}
