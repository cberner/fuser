use super::UnmountOption;
use super::fuse3_sys::{
    fuse_lowlevel_ops, fuse_session_destroy, fuse_session_fd, fuse_session_mount, fuse_session_new,
    fuse_session_unmount,
};
use super::{MountOption, unmount_options, with_fuse_args};
use log::warn;
use std::ffi::CStr;
use std::time::Duration;
use std::{
    ffi::{CString, c_int, c_void},
    fs::File,
    io,
    os::unix::{ffi::OsStrExt, io::FromRawFd},
    path::Path,
    ptr,
    sync::Arc,
};

/// Ensures that an os error is never 0/Success
fn ensure_last_os_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(0) => io::Error::new(io::ErrorKind::Other, "Unspecified Error"),
        _ => err,
    }
}

fn cvt(res: i32) -> io::Result<()> {
    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug)]
pub struct Mount {
    fuse_session: *mut c_void,
    mountpoint: CString,
    blocking_umount: bool,
    unmount_flags: Option<Vec<UnmountOption>>,
    unmounted: bool,
}
impl Mount {
    pub fn new(mnt: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        let mnt = CString::new(mnt.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, |args| {
            let ops = fuse_lowlevel_ops::default();

            let fuse_session = unsafe {
                fuse_session_new(
                    args,
                    &ops as *const _,
                    std::mem::size_of::<fuse_lowlevel_ops>(),
                    ptr::null_mut(),
                )
            };
            if fuse_session.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mount = Mount {
                fuse_session,
                mountpoint: mnt.clone(),
                blocking_umount: false,
                unmount_flags: None,
                unmounted: false,
            };
            let result = unsafe { fuse_session_mount(mount.fuse_session, mnt.as_ptr()) };
            if result != 0 {
                return Err(ensure_last_os_error());
            }
            let fd = unsafe { fuse_session_fd(mount.fuse_session) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // We dup the fd here as the existing fd is owned by the fuse_session, and we
            // don't want it being closed out from under us:
            let fd = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0))?;
            let file = unsafe { File::from_raw_fd(fd) };
            Ok((Arc::new(file), mount))
        })
    }

    /// Enable or disable blocking if the umount operation is busy
    pub fn set_blocking_unmount(&mut self, blocking: bool) {
        self.blocking_umount = blocking;
    }

    /// Override fuser's default umount behavior
    pub fn set_unmount_flags(&mut self, flags: Option<&[UnmountOption]>) {
        self.unmount_flags = flags.map(|f| f.to_vec());
    }

    /// Internal method for [`Self::unmount`] and [`Self::drop`]
    fn _unmount(&mut self) -> Result<(), (Self, io::Error)> {
        if self.unmounted {
            return Ok(());
        }
        if let Err(err) = fuse3_umount(
            self.fuse_session,
            &self.mountpoint,
            self.unmount_flags.as_deref(),
            self.blocking_umount,
        ) {
            return Err((self, err));
        }
        self.unmounted = true;
        Ok(())
    }

    /// Consume the Mount and unmount the filesystem
    pub fn unmount(mut self) -> Result<(), (Self, io::Error)> {
        if let Err(err) = self._unmount() {
            return Err((self, err));
        }
        Ok(())
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if let Err(err) = self._unmount() {
            error!("umount failed with {:?}", err);
        }
    }
}

unsafe impl Send for Mount {}

fn fuse3_umount(
    fuse_session: *mut c_void,
    mountpoint: &CStr,
    flags: Option<&[UnmountOption]>,
    blocking: bool,
) -> Result<(), io::Error> {
    #[cfg(target_os = "linux")]
    use std::io::ErrorKind::PermissionDenied;
    use std::io::ErrorKind::ResourceBusy;
    loop {
        let flags = flags.unwrap_or(&[]);
        let result = {
            // FIXME: Add umount fallback if linux version is <2.1.116
            #[cfg(target_os = "linux")]
            let res = cvt(unsafe {
                let int_flags = unmount_options::to_unmount_syscall(flags);
                libc::umount2(mountpoint.as_ptr(), int_flags)
            });
            #[cfg(target_os = "macos")]
            let res = cvt(unsafe {
                let int_flags = unmount_options::to_unmount_syscall(flags);
                libc::unmount(mountpoint.as_ptr(), int_flags)
            });
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let res = super::libc_umount(&mountpoint);
            res
        };
        let error = match result {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        // Block operation using a sleep wait until last handle is closed
        if error.kind() == ResourceBusy && blocking {
            std::thread::sleep(Duration::from_secs_f64(0.5));
            continue;
        }
        // Linux always returns EPERM for non-root users.  We have to let the
        // library go through the seqtuid-root "fusermount -u" to unmount.
        #[cfg(target_os = "linux")]
        if error.kind() == PermissionDenied {
            break;
        }
        return Err(error);
    }
    unsafe {
        fuse_session_unmount(fuse_session);
        fuse_session_destroy(fuse_session);
        return Ok(());
    }
}
