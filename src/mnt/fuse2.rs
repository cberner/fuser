use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::MountOption;
use crate::mnt::fuse2_sys::*;
use crate::mnt::libfuse_call;
use crate::mnt::with_fuse_args;

#[derive(Debug)]
pub(crate) struct MountImpl {
    mountpoint: CString,
}
impl MountImpl {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, acl, |args| {
            let fd = libfuse_call(
                "fuse_mount_compat25",
                || unsafe { fuse_mount_compat25(mountpoint.as_ptr(), args) },
                |fd| *fd >= 0,
            )?;
            let file = unsafe { File::from_raw_fd(fd) };
            Ok((Arc::new(DevFuse(file)), MountImpl { mountpoint }))
        })
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        // fuse_unmount_compat22 unfortunately doesn't return a status. Additionally,
        // it attempts to call realpath, which in turn calls into the filesystem. So
        // if the filesystem returns an error, the unmount does not take place, with
        // no indication of the error available to the caller. So we call unmount
        // directly, which is what osxfuse does anyway, since we already converted
        // to the real path when we first mounted.
        if let Err(err) = crate::mnt::libc_umount(&self.mountpoint) {
            // Linux always returns EPERM for non-root users.  We have to go
            // through the setuid-root "fusermount -u" to unmount.
            if err == nix::errno::Errno::EPERM {
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "openbsd",
                    target_os = "netbsd"
                )))]
                {
                    // Not libfuse's fuse_unmount_compat22: that would swallow
                    // fusermount failures (leaving a still-running session that
                    // callers then believe has been unmounted) and stat the
                    // mountpoint through the filesystem via realpath
                    return crate::mnt::fusermount_unmount("fusermount", &self.mountpoint);
                }
            }
            return Err(err.into());
        }
        Ok(())
    }
}
