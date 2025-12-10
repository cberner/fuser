use super::UnmountOption;
use super::{MountOption, fuse2_sys::*, unmount_options, with_fuse_args};
use log::warn;
use std::ffi::{CStr, c_int};
use std::time::Duration;
use std::{
    ffi::CString,
    fs::File,
    io,
    os::unix::prelude::{FromRawFd, OsStrExt},
    path::Path,
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

#[derive(Debug)]
pub struct Mount {
    mountpoint: CString,
    blocking_umount: bool,
    umount_flags: Option<Vec<UnmountOption>>,
}
impl Mount {
    pub fn new(mountpoint: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, |args| {
            let fd = unsafe { fuse_mount_compat25(mountpoint.as_ptr(), args) };
            if fd < 0 {
                Err(ensure_last_os_error())
            } else {
                let file = unsafe { File::from_raw_fd(fd) };
                Ok((
                    Arc::new(file),
                    Mount {
                        mountpoint,
                        blocking_umount: false,
                        umount_flags: None,
                    },
                ))
            }
        })
    }

    /// Enable or disable blocking if the umount operation is busy
    pub fn set_blocking_umount(&mut self, blocking: bool) {
        self.blocking_umount = blocking;
    }

    /// Override fuser's default umount behavior
    pub fn set_umount_flags(&mut self, flags: Option<&[UnmountOption]>) {
        self.umount_flags = flags.map(|f| f.to_vec());
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if let Err(err) = fuse2_umount(
            &self.mountpoint,
            self.umount_flags.as_deref(),
            self.blocking_umount,
        ) {
            warn!("umount failed with {:?}", err);
        }
    }
}

fn cvt(res: i32) -> io::Result<()> {
    if res == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fuse2_umount(
    mountpoint: &CStr,
    flags: Option<&[UnmountOption]>,
    blocking: bool,
) -> Result<(), io::Error> {
    use std::io::ErrorKind::PermissionDenied;
    use std::io::ErrorKind::ResourceBusy;
    loop {
        let flags = flags.unwrap_or(&[]);
        let int_flags = unmount_options::to_unmount_syscall(flags);
        let result = {
            // FIXME: Add umount fallback if linux version is <2.1.116
            #[cfg(target_os = "linux")]
            let res = cvt(unsafe {
                libc::umount2(mountpoint.as_ptr(), int_flags)
            });
            #[cfg(target_os = "macos")]
            let res = cvt(unsafe {
                libc::unmount(mountpoint.as_ptr(), int_flags)
            });
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let res = super::libc_umount(mountpoint);
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
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        if error.kind() == PermissionDenied {
            break;
        }
        return Err(error);
    }

    // fuse_unmount_compat22 unfortunately doesn't return a status. Additionally,
    // it attempts to call realpath, which in turn calls into the filesystem. So
    // if the filesystem returns an error, the unmount does not take place, with
    // no indication of the error available to the caller. So we call unmount
    // directly, which is what osxfuse does anyway, since we already converted
    // to the real path when we first mounted.
    unsafe {
        fuse_unmount_compat22(mountpoint.as_ptr());
        return Ok(());
    }
}
