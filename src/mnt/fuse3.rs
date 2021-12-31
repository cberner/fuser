use super::fuse3_sys::{
    fuse_session_destroy, fuse_session_fd, fuse_session_mount, fuse_session_new,
    fuse_session_unmount,
};
use super::{ensure_last_os_error, with_fuse_args, MountOption};
use std::{
    ffi::{c_void, CString},
    fs::File,
    io,
    os::unix::{ffi::OsStrExt, io::FromRawFd},
    path::Path,
    ptr,
    sync::Arc,
};

fn last_os_err_ctx(ctx: &'static str) -> io::Error {
    let err = io::Error::last_os_error();
    io::Error::new(err.kind(), format!("libfuse error during {}: {}", ctx, err))
}

#[derive(Debug)]
pub struct Mount {
    fuse_session: *mut c_void,
}
impl Mount {
    pub fn new(mnt: &Path, options: &[MountOption]) -> io::Result<(Arc<File>, Mount)> {
        let mnt = CString::new(mnt.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, |args| {
            let fuse_session = unsafe { fuse_session_new(args, ptr::null(), 0, ptr::null_mut()) };
            if fuse_session.is_null() {
                return Err(last_os_err_ctx("fuse_session_new"));
            }
            let mount = Mount { fuse_session };
            let result = unsafe { fuse_session_mount(mount.fuse_session, mnt.as_ptr()) };
            if result != 0 {
                return Err(last_os_err_ctx("fuse_session_mount"));
            }
            let fd = unsafe { fuse_session_fd(mount.fuse_session) };
            if fd < 0 {
                return Err(last_os_err_ctx("fuse_session_fd"));
            }
            // We dup the fd here as the existing fd is owned by the fuse_session, and we
            // don't want it being closed out from under us:
            let fd = unsafe { libc::dup(fd) };
            if fd < 0 {
                return Err(last_os_err_ctx("dup"));
            }
            let file = unsafe { File::from_raw_fd(fd) };
            Ok((Arc::new(file), mount))
        })
    }
}
impl Drop for Mount {
    fn drop(&mut self) {
        unsafe {
            fuse_session_unmount(self.fuse_session);
            fuse_session_destroy(self.fuse_session);
        }
    }
}
unsafe impl Send for Mount {}
