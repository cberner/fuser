use std::ffi::CString;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use super::MountOption;
use super::fuse3_sys::fuse_lowlevel_ops;
use super::fuse3_sys::fuse_session_destroy;
use super::fuse3_sys::fuse_session_fd;
use super::fuse3_sys::fuse_session_mount;
use super::fuse3_sys::fuse_session_new;
use super::fuse3_sys::fuse_session_unmount;
use super::unmount_options::UnmountOption;
use super::with_fuse_args;
use crate::dev_fuse::DevFuse;

#[derive(Debug)]
pub(crate) struct MountImpl {
    fuse_session: *mut c_void,
    mountpoint: CString,
}

impl MountImpl {
    pub(crate) fn new(
        mnt: &Path,
        options: &[MountOption],
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let mnt = CString::new(mnt.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, |args| {
            let ops = fuse_lowlevel_ops::default();

            let fuse_session = unsafe {
                fuse_session_new(
                    args,
                    &ops as *const _,
                    size_of::<fuse_lowlevel_ops>(),
                    ptr::null_mut(),
                )
            };
            if fuse_session.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mount = MountImpl {
                fuse_session,
                mountpoint: mnt.clone(),
            };
            let result = unsafe { fuse_session_mount(mount.fuse_session, mnt.as_ptr()) };
            if result != 0 {
                return Err(ensure_last_os_error());
            }
            let fd = unsafe { fuse_session_fd(mount.fuse_session) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
            // We dup the fd here as the existing fd is owned by the fuse_session, and we
            // don't want it being closed out from under us:
            let fd = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0))?;
            let file = unsafe { File::from_raw_fd(fd) };
            Ok((Arc::new(DevFuse(file)), mount))
        })
    }

    pub(crate) fn umount_impl(&mut self, flags: &[UnmountOption]) -> io::Result<()> {
        use std::io::ErrorKind::PermissionDenied;

        if let Err(err) = super::libc_umount(&self.mountpoint, flags) {
            // Linux always returns EPERM for non-root users.  We have to let the
            // library go through the setuid-root "fusermount -u" to unmount.
            if err.kind() == PermissionDenied {
                #[cfg(target_os = "linux")]
                unsafe {
                    fuse_session_unmount(self.fuse_session);
                    fuse_session_destroy(self.fuse_session);
                    return Ok(());
                }
            }
            return Err(err);
        }
        Ok(())
    }
}

unsafe impl Send for MountImpl {}
