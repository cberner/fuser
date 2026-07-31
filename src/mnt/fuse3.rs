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
use crate::mnt::libfuse_call;
use crate::mnt::with_fuse_args;

#[derive(Debug)]
pub(crate) struct MountImpl {
    fuse_session: *mut c_void,
    mountpoint: CString,
}
impl MountImpl {
    pub(crate) fn new(
        mnt: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let mnt = CString::new(mnt.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, acl, |args| {
            let ops = fuse_lowlevel_ops::default();

            let fuse_session = libfuse_call(
                "fuse_session_new",
                || unsafe {
                    fuse_session_new(
                        args,
                        &ops as *const _,
                        size_of::<fuse_lowlevel_ops>(),
                        ptr::null_mut(),
                    )
                },
                |session| !session.is_null(),
            )?;
            // Construct the guard before the fallible setup steps, so an early
            // return destroys the session via Drop instead of leaking it
            let mount = MountImpl {
                fuse_session,
                mountpoint: mnt,
            };
            libfuse_call(
                "fuse_session_mount",
                || unsafe { fuse_session_mount(mount.fuse_session, mount.mountpoint.as_ptr()) },
                |result| *result == 0,
            )?;
            let fd = libfuse_call(
                "fuse_session_fd",
                || unsafe { fuse_session_fd(mount.fuse_session) },
                |fd| *fd >= 0,
            )?;
            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
            // We dup the fd here as the existing fd is owned by the fuse_session, and we
            // don't want it being closed out from under us:
            let fd = fd.try_clone_to_owned()?;
            let file = File::from(fd);
            Ok((Arc::new(DevFuse(file)), mount))
        })
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        if let Err(err) = crate::mnt::libc_umount(&self.mountpoint) {
            // Linux always returns EPERM for non-root users.  We have to let the
            // library go through the setuid-root "fusermount -u" to unmount.
            if err == nix::errno::Errno::EPERM {
                #[cfg(target_os = "linux")]
                {
                    unsafe {
                        fuse_session_unmount(self.fuse_session);
                        fuse_session_destroy(self.fuse_session);
                    }
                    self.fuse_session = ptr::null_mut();
                    return Ok(());
                }
            }
            return Err(err.into());
        }
        Ok(())
    }
}

impl Drop for MountImpl {
    fn drop(&mut self) {
        // Free the session on every teardown path (it may already be gone if
        // umount_impl went through fuse_session_unmount). This only releases the
        // session's resources; any unmounting has been done by umount_impl, or was
        // deliberately skipped because the filesystem is no longer mounted
        if !self.fuse_session.is_null() {
            unsafe {
                fuse_session_destroy(self.fuse_session);
            }
            self.fuse_session = ptr::null_mut();
        }
    }
}

unsafe impl Send for MountImpl {}
