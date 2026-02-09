use std::ffi::CString;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use log::error;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::MountOption;
use crate::mnt::UnmountOption;
use crate::mnt::fuse3_sys::fuse_lowlevel_ops;
use crate::mnt::fuse3_sys::fuse_session_destroy;
use crate::mnt::fuse3_sys::fuse_session_fd;
use crate::mnt::fuse3_sys::fuse_session_mount;
use crate::mnt::fuse3_sys::fuse_session_new;
use crate::mnt::fuse3_sys::fuse_session_unmount;
use crate::mnt::fusermount;
use crate::mnt::is_mounted;
use crate::mnt::with_fuse_args;

fn ensure_last_os_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(0) => io::Error::new(io::ErrorKind::Other, "Unspecified Error"),
        _ => err,
    }
}

#[derive(Debug)]
pub(crate) struct MountImpl {
    fuse_session: FuseSession,
}

#[derive(Debug)]
struct FuseSession {
    inner: *mut c_void,
    state: Option<MountState>,
}

#[derive(Debug)]
struct MountState {
    mountpoint: PathBuf,
    device: Arc<DevFuse>,
}

unsafe impl Send for FuseSession {}

impl FuseSession {
    fn new(args: &mut super::fuse_args, ops: &fuse_lowlevel_ops) -> io::Result<Self> {
        let fuse_session = unsafe {
            fuse_session_new(
                // args is zeroed out if it is parsed once, so it has to be denoted as mut
                args,
                ops,
                size_of::<fuse_lowlevel_ops>(),
                ptr::null_mut(),
            )
        };
        if fuse_session.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            inner: fuse_session,
            state: None,
        })
    }

    fn mount(&mut self, mnt: &Path) -> io::Result<()> {
        // If the filesystem is already mounted, return an error
        if let Some(state) = &self.state {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Filesystem is already mounted on {}",
                    state.mountpoint.display()
                ),
            ));
        }
        let mnt_cstr = CString::new(mnt.as_os_str().as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid mount path: {}", e),
            )
        })?;
        // FIXME/SAFETY: If AutoUnmount is enabled, this function leaks the fusermount
        // communication socket fd[1] used for receiving the FUSE fd from fusermount
        // and unmounting on socket removal. This may cause problems with long
        // running processes. The file descriptor is left on `_FUSE_COMMFD2`.
        let result = unsafe { fuse_session_mount(self.inner, mnt_cstr.as_ptr()) };
        if result != 0 {
            return Err(ensure_last_os_error());
        }
        // Do not allow the mount or device to persist if the file descriptor
        // cannot be cloned.
        let device = self.try_clone_to_file().inspect_err(|_| {
            unsafe { fuse_session_unmount(self.inner) };
        })?;
        self.state = Some(MountState {
            mountpoint: mnt.to_owned(),
            device: Arc::new(DevFuse(device)),
        });
        Ok(())
    }

    fn unmount(&mut self, flags: &[UnmountOption]) -> io::Result<()> {
        // FIXME: Detect mismatching/shadowing mounts
        let state = match self.state.as_mut() {
            None => return Ok(()),
            Some(state) => state,
        };
        // Checks if the filesystem is still mounted - if it not mounted,
        // do not call the unmount functions below.
        if !is_mounted(&state.device) {
            self.user_unmount_and_clear();
            return Ok(());
        }
        if let Err(err) = crate::mnt::libc_umount(&state.mountpoint, flags) {
            // If the filesystem is gone, we need to clear the state and prevent the
            // unmount function from being called again
            if !is_mounted(&state.device) {
                self.user_unmount_and_clear();
            }
            // Linux always returns EPERM for non-root users.  We have to let the
            // library go through the setuid-root "fusermount -u" to unmount.
            else if err == nix::errno::Errno::EPERM {
                if let Err(e) = fusermount::fuse_unmount_pure(&state.mountpoint, flags) {
                    if !is_mounted(&state.device) {
                        self.user_unmount_and_clear();
                    }
                    return Err(e);
                }
                self.user_unmount_and_clear();
                return Ok(());
            }
            return Err(err.into());
        }
        self.user_unmount_and_clear();
        Ok(())
    }

    fn mountpoint(&self) -> Option<&Path> {
        self.state.as_ref().map(|p| p.mountpoint.as_path())
    }

    fn fd(&self) -> Option<BorrowedFd<'_>> {
        let fd = unsafe { fuse_session_fd(self.inner) };
        if fd < 0 {
            return None;
        }
        Some(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    fn try_clone_to_file(&self) -> io::Result<File> {
        let fd = self.fd().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "No file descriptor available")
        })?;
        let owned_fd = fd.try_clone_to_owned()?;
        let file = File::from(owned_fd);
        Ok(file)
    }

    fn get_device(&self) -> Option<Arc<DevFuse>> {
        self.state.as_ref().map(|state| state.device.clone())
    }

    // Ensures the internal session is unmounted (internal mountpoint must be freed,
    // the unmount must be done, and the fd is set to -1) and the state is cleared.
    fn user_unmount_and_clear(&mut self) {
        // The function is idempotent as long as there are no mounts shadowing it.
        unsafe { fuse_session_unmount(self.inner) };
        self.state = None;
    }

    fn is_alive(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| is_mounted(&state.device))
    }
}

impl Drop for FuseSession {
    fn drop(&mut self) {
        let flags = super::drop_umount_flags();
        if let Err(err) = super::with_retry_on_busy_or_again(|| self.unmount(flags)) {
            error!(
                "Failed to unmount filesystem on mountpoint {:?}: {}",
                self.mountpoint(),
                err
            );
        }
        // Forcibly call unmount again to free its internal data.
        self.user_unmount_and_clear();
        // Clean up the internal mount object.
        unsafe {
            fuse_session_destroy(self.inner);
        }
    }
}

impl MountImpl {
    pub(crate) fn new(
        mnt: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let mnt = mnt.canonicalize()?;
        with_fuse_args(options, acl, |args| {
            let ops = fuse_lowlevel_ops::default();
            let mut session = FuseSession::new(args, &ops)?;
            session.mount(&mnt)?;
            let file = session
                .get_device()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No device available"))?;
            Ok((
                file,
                MountImpl {
                    fuse_session: session,
                },
            ))
        })
    }

    pub(crate) fn umount_impl(&mut self, flags: &[UnmountOption]) -> io::Result<()> {
        self.fuse_session.unmount(flags)
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.fuse_session.is_alive()
    }
}

unsafe impl Send for MountImpl {}
