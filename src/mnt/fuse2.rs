use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use log::error;

use super::is_mounted;
use super::unmount_options::UnmountOption;
use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::MountOption;
use crate::mnt::fuse2_sys::*;
use crate::mnt::fusermount;
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
    state: Option<MountState>,
}

#[derive(Debug)]
struct MountState {
    mountpoint: PathBuf,
    device: Arc<DevFuse>,
}

impl MountImpl {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let mountpoint = mountpoint.canonicalize()?;
        let mountpoint_cstr = CString::new(mountpoint.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid mountpoint path {}", mountpoint.display()),
            )
        })?;
        with_fuse_args(options, acl, |args| {
            // FIXME/SAFETY: If AutoUnmount is enabled, this function leaks the fusermount
            // communication socket fd[1] used for receiving the FUSE fd from fusermount
            // and unmounting on socket removal. This may cause problems with long
            // running processes. The file descriptor is left on `_FUSE_COMMFD2`.
            let fd = unsafe { fuse_mount_compat25(mountpoint_cstr.as_ptr(), args) };
            if fd < 0 {
                Err(ensure_last_os_error())
            } else {
                let file = unsafe { File::from_raw_fd(fd) };
                let device = Arc::new(DevFuse(file));
                Ok((
                    device.clone(),
                    MountImpl {
                        state: Some(MountState {
                            mountpoint: mountpoint.to_path_buf(),
                            device,
                        }),
                    },
                ))
            }
        })
    }

    fn mountpoint(&self) -> Option<&Path> {
        self.state.as_ref().map(|state| state.mountpoint.as_path())
    }

    pub(crate) fn umount_impl(&mut self, flags: &[UnmountOption]) -> io::Result<()> {
        let state = match self.state.as_mut() {
            None => return Ok(()),
            Some(state) => state,
        };
        // If the filesystem is already unmounted, return early.
        if !is_mounted(&state.device) {
            self.state = None;
            return Ok(());
        }
        if let Err(err) = super::libc_umount(&state.mountpoint, flags) {
            // If the filesystem is gone, we need to clear the state and prevent the
            // unmount function from being called again
            if !is_mounted(&state.device) {
                self.state = None;
            }
            // Linux always returns EPERM for non-root users.  We have to let the
            // library go through the setuid-root "fusermount -u" to unmount.
            else if err == nix::errno::Errno::EPERM {
                if let Err(e) = fusermount::fuse_unmount_pure(&state.mountpoint, flags) {
                    if !is_mounted(&state.device) {
                        self.state = None;
                    }
                    return Err(e);
                }
                self.state = None;
                return Ok(());
            }
            return Err(err.into());
        }
        self.state = None;
        Ok(())
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.state
            .as_ref()
            .map_or(false, |state| is_mounted(&state.device))
    }
}

impl Drop for MountImpl {
    fn drop(&mut self) {
        let flags = super::drop_umount_flags();
        if let Err(err) = super::with_retry_on_busy_or_again(|| self.umount_impl(&flags)) {
            error!(
                "Failed to unmount filesystem on mountpoint {:?}: {}",
                self.mountpoint(),
                err
            );
        }
        self.state = None;
    }
}
