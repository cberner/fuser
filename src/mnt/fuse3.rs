use std::ffi::CString;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::MountOption;
use crate::mnt::fuse3_sys::fuse_lowlevel_ops;
use crate::mnt::fuse3_sys::fuse_session_destroy;
use crate::mnt::fuse3_sys::fuse_session_fd;
use crate::mnt::fuse3_sys::fuse_session_mount;
use crate::mnt::fuse3_sys::fuse_session_new;
use crate::mnt::fuse3_sys::fuse_session_unmount;
use crate::mnt::with_fuse_args;

/// Ensures that an os error is never 0/Success
fn ensure_last_os_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(0) => io::Error::new(io::ErrorKind::Other, "Unspecified Error"),
        _ => err,
    }
}

#[derive(Debug)]
pub(crate) struct MountImpl {
    fuse_session: *mut c_void,
    _mountpoint: CString,
}

impl MountImpl {
    pub(crate) fn new(
        mnt: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        log::warn!(
            "Using libfuse3 as the mount backend may cause memory leaks in some scenarios, for example, if AutoUnmount is set."
        );
        let mnt = CString::new(mnt.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, acl, |args| {
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
                _mountpoint: mnt.clone(),
            };
            let result = unsafe { fuse_session_mount(mount.fuse_session, mnt.as_ptr()) };
            if result != 0 {
                unsafe {
                    fuse_session_destroy(fuse_session);
                }
                return Err(ensure_last_os_error());
            }
            let fd = unsafe { fuse_session_fd(mount.fuse_session) };
            if fd < 0 {
                unsafe {
                    fuse_session_unmount(fuse_session);
                    fuse_session_destroy(fuse_session);
                }
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
            // We dup the fd here as the existing fd is owned by the fuse_session, and we
            // don't want it being closed out from under us:
            let fd = fd.try_clone_to_owned().inspect_err(|_| unsafe {
                fuse_session_unmount(fuse_session);
                fuse_session_destroy(fuse_session);
            })?;
            let file = File::from(fd);
            Ok((Arc::new(DevFuse(file)), mount))
        })
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        // Because fuse_session_new and fuse_session_mount were called, which initializes FFI structures, libfuse expects these 2 functions to be called unconditionally to clean up, or a structure leak will occur (alongside the auto unmount fd leak which is unfixable)
        unsafe {
            fuse_session_unmount(self.fuse_session);
            fuse_session_destroy(self.fuse_session);
        };
        Ok(())
    }
}
unsafe impl Send for MountImpl {}
