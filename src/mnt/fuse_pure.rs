//! Native FFI bindings to libfuse.
//!
//! This is a small set of bindings that are required to mount/unmount FUSE filesystems and
//! open/close a fd to the FUSE kernel driver.

#![warn(missing_debug_implementations)]
#![allow(missing_docs)]

use super::is_mounted;
use super::mount_options::{MountOption, option_to_string};
use log::{debug, error};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
))]
use std::io;
use std::io::{Error, ErrorKind, IoSliceMut, Read};
use std::mem;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use crate::dev_fuse::DevFuse;

const FUSERMOUNT_BIN: &str = "fusermount";
const FUSERMOUNT3_BIN: &str = "fusermount3";
const FUSERMOUNT_COMM_ENV: &str = "_FUSE_COMMFD";
const MOUNT_FUSEFS_BIN: &str = "mount_fusefs";

#[derive(Debug)]
pub(crate) struct Mount {
    mountpoint: CString,
    auto_unmount_socket: Option<UnixStream>,
    fuse_device: Arc<DevFuse>,
}
impl Mount {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
    ) -> io::Result<(Arc<DevFuse>, Mount)> {
        let mountpoint = mountpoint.canonicalize()?;
        let (file, sock) = fuse_mount_pure(mountpoint.as_os_str(), options)?;
        let file = Arc::new(file);
        Ok((
            file.clone(),
            Mount {
                mountpoint: CString::new(mountpoint.as_os_str().as_bytes())?,
                auto_unmount_socket: sock,
                fuse_device: file,
            },
        ))
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if !is_mounted(&self.fuse_device) {
            // If the filesystem has already been unmounted, avoid unmounting it again.
            // Unmounting it a second time could cause a race with a newly mounted filesystem
            // living at the same mountpoint
            return;
        }
        if let Some(sock) = mem::take(&mut self.auto_unmount_socket) {
            drop(sock);
            // fusermount in auto-unmount mode, no more work to do.
            return;
        }
        if let Err(err) = super::libc_umount(&self.mountpoint) {
            if err.kind() == ErrorKind::PermissionDenied {
                // Linux always returns EPERM for non-root users.  We have to let the
                // library go through the setuid-root "fusermount -u" to unmount.
                fuse_unmount_pure(&self.mountpoint)
            } else {
                error!("Unmount failed: {}", err)
            }
        }
    }
}

fn fuse_mount_pure(
    mountpoint: &OsStr,
    options: &[MountOption],
) -> Result<(DevFuse, Option<UnixStream>), io::Error> {
    if options.contains(&MountOption::AutoUnmount) {
        // Auto unmount is only supported via fusermount
        return fuse_mount_fusermount(mountpoint, options);
    }

    // The direct mount path is currently implemented only for Linux and macOS.
    // Other supported Unix targets (such as the BSDs) rely on the setuid
    // mount helper, which mirrors libfuse's approach.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        return fuse_mount_fusermount(mountpoint, options);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let res = fuse_mount_sys(mountpoint, options)?;
        match res {
            Some(file) => Ok((file, None)),
            _ => {
                // Retry
                fuse_mount_fusermount(mountpoint, options)
            }
        }
    }
}

fn fuse_unmount_pure(mountpoint: &CStr) {
    #[cfg(target_os = "linux")]
    unsafe {
        let result = libc::umount2(mountpoint.as_ptr(), libc::MNT_DETACH);
        if result == 0 {
            return;
        }
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let result = libc::unmount(mountpoint.as_ptr(), libc::MNT_FORCE);
        if result == 0 {
            return;
        }
    }

    let mut builder = Command::new(detect_fusermount_bin());
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    builder
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(OsStr::new(&mountpoint.to_string_lossy().into_owned()));

    if let Ok(output) = builder.output() {
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stdout));
        debug!("fusermount: {}", String::from_utf8_lossy(&output.stderr));
    }
}

fn detect_fusermount_bin() -> String {
    for name in [
        FUSERMOUNT3_BIN.to_string(),
        FUSERMOUNT_BIN.to_string(),
        MOUNT_FUSEFS_BIN.to_string(),
        format!("/sbin/{FUSERMOUNT3_BIN}"),
        format!("/sbin/{FUSERMOUNT_BIN}"),
        format!("/sbin/{MOUNT_FUSEFS_BIN}"),
        format!("/bin/{FUSERMOUNT3_BIN}"),
        format!("/bin/{FUSERMOUNT_BIN}"),
    ]
    .iter()
    {
        if Command::new(name).arg("-h").output().is_ok() {
            return name.to_string();
        }
    }
    // Default to fusermount3
    FUSERMOUNT3_BIN.to_string()
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

fn fuse_mount_fusermount(
    mountpoint: &OsStr,
    options: &[MountOption],
) -> Result<(DevFuse, Option<UnixStream>), Error> {
    let fusermount_bin = detect_fusermount_bin();

    if fusermount_bin.ends_with(MOUNT_FUSEFS_BIN) {
        return fuse_mount_mount_fusefs(&fusermount_bin, mountpoint, options);
    }

    let (child_socket, receive_socket) = UnixStream::pair()?;

    // TODO: do not ignore error.
    let _ = fcntl(&child_socket, FcntlArg::F_SETFD(FdFlag::empty()));

    let mut builder = Command::new(&fusermount_bin);
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    if !options.is_empty() {
        builder.arg("-o");
        let options_strs: Vec<String> = options.iter().map(option_to_string).collect();
        builder.arg(options_strs.join(","));
    }
    builder
        .arg("--")
        .arg(mountpoint)
        .env(FUSERMOUNT_COMM_ENV, child_socket.as_raw_fd().to_string());

    let fusermount_child = builder.spawn()?;

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
) -> Result<(DevFuse, Option<UnixStream>), Error> {
    let fuse_device = DevFuse::open()?;

    let fuse_fd = fuse_device.as_raw_fd();

    let mut builder = Command::new(fusermount_bin);
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    if !options.is_empty() {
        builder.arg("-o");
        let options_strs: Vec<String> = options.iter().map(option_to_string).collect();
        builder.arg(options_strs.join(","));
    }

    builder.arg(fuse_fd.to_string()).arg(mountpoint);

    unsafe {
        builder.pre_exec(move || {
            let fd = BorrowedFd::borrow_raw(fuse_fd);
            let current_flags = fcntl(fd, FcntlArg::F_GETFD)?;
            let current_flags = FdFlag::from_bits_retain(current_flags);
            if current_flags.contains(FdFlag::FD_CLOEXEC) {
                let cleared = current_flags & !FdFlag::FD_CLOEXEC;
                fcntl(fd, FcntlArg::F_SETFD(cleared))?;
            }
            Ok(())
        });
    }

    let output = builder.output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            ErrorKind::Other,
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok((fuse_device, None))
}

// If returned option is none. Then fusermount binary should be tried
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fuse_mount_sys(mountpoint: &OsStr, options: &[MountOption]) -> Result<Option<DevFuse>, Error> {
    let mountpoint_mode = File::open(mountpoint)?.metadata()?.permissions().mode();

    // Auto unmount requests must be sent to fusermount binary
    assert!(!options.contains(&MountOption::AutoUnmount));

    let file = match DevFuse::open() {
        Ok(dev_fuse) => dev_fuse,
        Err(error) => {
            if error.kind() == ErrorKind::NotFound {
                error!("{} not found. Try 'modprobe fuse'", DevFuse::PATH);
            }
            return Err(error);
        }
    };
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

    let mut flags = 0;
    if !options.contains(&MountOption::Dev) {
        // Default to nodev
        #[cfg(target_os = "linux")]
        {
            flags |= libc::MS_NODEV;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= libc::MNT_NODEV;
        }
    }
    if !options.contains(&MountOption::Suid) {
        // Default to nosuid
        #[cfg(target_os = "linux")]
        {
            flags |= libc::MS_NOSUID;
        }
        #[cfg(target_os = "macos")]
        {
            flags |= libc::MNT_NOSUID;
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

    let c_source = CString::new(source).unwrap();
    let c_mountpoint = CString::new(mountpoint.as_bytes()).unwrap();

    let result = unsafe {
        #[cfg(target_os = "linux")]
        {
            let c_options = CString::new(mount_options.clone()).unwrap();
            let c_type = CString::new("fuse").unwrap();
            libc::mount(
                c_source.as_ptr(),
                c_mountpoint.as_ptr(),
                c_type.as_ptr(),
                flags,
                c_options.as_ptr() as *const libc::c_void,
            )
        }
        #[cfg(target_os = "macos")]
        {
            let mut c_options = CString::new(mount_options.clone()).unwrap();
            libc::mount(
                c_source.as_ptr(),
                c_mountpoint.as_ptr(),
                flags,
                c_options.as_ptr() as *mut libc::c_void,
            )
        }
    };
    if result == -1 {
        let err = Error::last_os_error();
        if err.kind() == ErrorKind::PermissionDenied {
            return Ok(None); // Retry with fusermount
        } else {
            return Err(Error::new(
                err.kind(),
                format!(
                    "Error calling mount() at {mountpoint:?} with {mount_options:?} and flags={flags}: {err}"
                ),
            ));
        }
    }

    Ok(Some(file))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(dead_code)]
fn fuse_mount_sys(_mountpoint: &OsStr, _options: &[MountOption]) -> Result<Option<DevFuse>, Error> {
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(PartialEq)]
pub(crate) enum MountOptionGroup {
    KernelOption,
    KernelFlag,
    Fusermount,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn option_group(option: &MountOption) -> MountOptionGroup {
    match option {
        MountOption::FSName(_) => MountOptionGroup::Fusermount,
        MountOption::Subtype(_) => MountOptionGroup::Fusermount,
        MountOption::CUSTOM(_) => MountOptionGroup::KernelOption,
        MountOption::AutoUnmount => MountOptionGroup::Fusermount,
        MountOption::AllowOther => MountOptionGroup::KernelOption,
        MountOption::Dev => MountOptionGroup::KernelFlag,
        MountOption::NoDev => MountOptionGroup::KernelFlag,
        MountOption::Suid => MountOptionGroup::KernelFlag,
        MountOption::NoSuid => MountOptionGroup::KernelFlag,
        MountOption::RO => MountOptionGroup::KernelFlag,
        MountOption::RW => MountOptionGroup::KernelFlag,
        MountOption::Exec => MountOptionGroup::KernelFlag,
        MountOption::NoExec => MountOptionGroup::KernelFlag,
        MountOption::Atime => MountOptionGroup::KernelFlag,
        MountOption::NoAtime => MountOptionGroup::KernelFlag,
        MountOption::DirSync => MountOptionGroup::KernelFlag,
        MountOption::Sync => MountOptionGroup::KernelFlag,
        MountOption::Async => MountOptionGroup::KernelFlag,
        MountOption::AllowRoot => MountOptionGroup::KernelOption,
        MountOption::DefaultPermissions => MountOptionGroup::KernelOption,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn option_to_flag(option: &MountOption) -> io::Result<libc::c_ulong> {
    match option {
        MountOption::Dev => Ok(0), // There is no option for dev. It's the absence of NoDev
        MountOption::NoDev => Ok(libc::MS_NODEV),
        MountOption::Suid => Ok(0),
        MountOption::NoSuid => Ok(libc::MS_NOSUID),
        MountOption::RW => Ok(0),
        MountOption::RO => Ok(libc::MS_RDONLY),
        MountOption::Exec => Ok(0),
        MountOption::NoExec => Ok(libc::MS_NOEXEC),
        MountOption::Atime => Ok(0),
        MountOption::NoAtime => Ok(libc::MS_NOATIME),
        MountOption::Async => Ok(0),
        MountOption::Sync => Ok(libc::MS_SYNCHRONOUS),
        MountOption::DirSync => Ok(libc::MS_DIRSYNC),
        option => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid mount option for flag conversion: {option:?}"),
        )),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn option_to_flag(option: &MountOption) -> io::Result<libc::c_int> {
    match option {
        MountOption::Dev => Ok(0), // There is no option for dev. It's the absence of NoDev
        MountOption::NoDev => Ok(libc::MNT_NODEV),
        MountOption::Suid => Ok(0),
        MountOption::NoSuid => Ok(libc::MNT_NOSUID),
        MountOption::RW => Ok(0),
        MountOption::RO => Ok(libc::MNT_RDONLY),
        MountOption::Exec => Ok(0),
        MountOption::NoExec => Ok(libc::MNT_NOEXEC),
        MountOption::Atime => Ok(0),
        MountOption::NoAtime => Ok(libc::MNT_NOATIME),
        MountOption::Async => Ok(0),
        MountOption::Sync => Ok(libc::MNT_SYNCHRONOUS),
        option => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid mount option for flag conversion: {option:?}"),
        )),
    }
}

#[cfg_attr(
    any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ),
    allow(dead_code)
)]
#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub(crate) fn option_to_flag(option: &MountOption) -> io::Result<libc::c_int> {
    match option {
        MountOption::Dev => Ok(0),
        #[cfg(target_os = "freebsd")]
        MountOption::NoDev => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NoDev option is not supported on FreeBSD",
        )),
        #[cfg(not(target_os = "freebsd"))]
        MountOption::NoDev => Ok(libc::MNT_NODEV),
        MountOption::Suid => Ok(0),
        MountOption::NoSuid => Ok(libc::MNT_NOSUID),
        MountOption::RW => Ok(0),
        MountOption::RO => Ok(libc::MNT_RDONLY),
        MountOption::Exec => Ok(0),
        MountOption::NoExec => Ok(libc::MNT_NOEXEC),
        MountOption::Atime => Ok(0),
        MountOption::NoAtime => Ok(libc::MNT_NOATIME),
        MountOption::Async => Ok(0),
        MountOption::Sync => Ok(libc::MNT_SYNCHRONOUS),
        MountOption::DirSync => Ok(libc::MNT_SYNCHRONOUS),
        option => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid mount option for flag conversion: {option:?}"),
        )),
    }
}
