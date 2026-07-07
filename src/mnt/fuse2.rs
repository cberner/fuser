use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::MountOption;
use crate::mnt::fuse2_sys::*;
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
    mountpoint: CString,
    fuse_device: Arc<DevFuse>,
}

impl MountImpl {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        log::warn!(
            "Using libfuse2 as the mount backend may cause memory leaks in some scenarios, for example, if AutoUnmount is set."
        );
        let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, acl, |args| {
            let fd = unsafe { fuse_mount_compat25(mountpoint.as_ptr(), args) };
            if fd < 0 {
                Err(ensure_last_os_error())
            } else {
                let file = unsafe { File::from_raw_fd(fd) };
                let devfuse = Arc::new(DevFuse(file));
                Ok((
                    devfuse.clone(),
                    MountImpl {
                        mountpoint,
                        fuse_device: devfuse,
                    },
                ))
            }
        })
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        // fuse_unmount_compat22 unfortunately doesn't return a status. Additionally,
        // it attempts to call realpath, which in turn calls into the filesystem. So
        // if the filesystem returns an error, the unmount does not take place, with
        // no indication of the error available to the caller. So we call unmount
        // directly, which is what osxfuse does anyway, since we already converted
        // to the real path when we first mounted.
        super::retry_on_unmount_errors(
            || {
                if !super::is_mounted(&self.fuse_device) {
                    // If the filesystem has already been unmounted, avoid unmounting it again.
                    // Unmounting it a second time could cause a race with a newly mounted filesystem
                    // living at the same mountpoint
                    return Ok(());
                }
                if let Err(err) = crate::mnt::libc_umount(&self.mountpoint) {
                    // Linux always returns EPERM for non-root users.  We have to let the
                    // library go through the setuid-root "fusermount -u" to unmount.
                    if err == nix::errno::Errno::EPERM {
                        unsafe {
                            fuse_unmount_compat22(self.mountpoint.as_ptr());
                            return Ok(());
                        }
                    }
                    return Err(err.into());
                }
                Ok(())
            },
            &self.mountpoint,
            Duration::from_secs(1),
        )
    }
}

#[cfg(test)]
mod tests {
    /// Scenario: this serves as a complementary test to session::tests::test_session_early_unmount. macFUSE apparently does not materialize the mountpoint in the mount table right away, so the kernel responds with EINVAL. The mountpoint only appears after the handshake is complete.
    #[cfg(target_os = "macos")]
    #[test_log::test]
    fn test_mac_fuse2_umount_impl() {
        use super::*;

        let test_dir = tempfile::tempdir().expect("failed to create test directory");
        log::info!("Test directory: {:?}", test_dir.path());
        let mut mount = MountImpl::new(test_dir.path(), &[], SessionACL::Owner)
            .expect("failed to mount filesystem");
        let err = mount
            .1
            .umount_impl()
            .expect_err("failed to unmount filesystem");
        assert_eq!(
            err.raw_os_error(),
            Some(nix::errno::Errno::EINVAL as i32),
            "macFUSE 5.2.0 should not materialize the mountpoint in the mount table"
        );
    }
}
