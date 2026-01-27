//! FUSE kernel driver communication
//!
//! Raw communication channel to the FUSE kernel driver.

#[cfg(fuser_mount_impl = "libfuse2")]
mod fuse2;
#[cfg(any(test, fuser_mount_impl = "libfuse2", fuser_mount_impl = "libfuse3"))]
mod fuse2_sys;
#[cfg(fuser_mount_impl = "libfuse3")]
mod fuse3;
#[cfg(fuser_mount_impl = "libfuse3")]
mod fuse3_sys;

#[cfg(fuser_mount_impl = "pure-rust")]
mod fuse_pure;
pub(crate) mod mount_options;
pub(crate) mod unmount_options;

use std::io;

#[cfg(any(test, fuser_mount_impl = "libfuse2", fuser_mount_impl = "libfuse3"))]
use fuse2_sys::fuse_args;
use log::error;
use mount_options::MountOption;
use unmount_options::UnmountOption;

use crate::dev_fuse::DevFuse;

/// Helper function to provide options as a `fuse_args` struct
/// (which contains an argc count and an argv pointer)
#[cfg(any(test, fuser_mount_impl = "libfuse2", fuser_mount_impl = "libfuse3"))]
fn with_fuse_args<T, F: FnOnce(&fuse_args) -> T>(options: &[MountOption], f: F) -> T {
    use std::ffi::CString;

    use mount_options::option_to_string;

    let mut args = vec![CString::new("rust-fuse").unwrap()];
    for x in options {
        args.extend_from_slice(&[
            CString::new("-o").unwrap(),
            CString::new(option_to_string(x)).unwrap(),
        ]);
    }
    let argptrs: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
    f(&fuse_args {
        argc: argptrs.len() as i32,
        argv: argptrs.as_ptr(),
        allocated: 0,
    })
}

use std::ffi::CStr;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) enum MountBacker {
    #[cfg(fuser_mount_impl = "pure-rust")]
    Pure(fuse_pure::MountImpl),
    #[cfg(fuser_mount_impl = "libfuse2")]
    Fuse2(fuse2::MountImpl),
    #[cfg(fuser_mount_impl = "libfuse3")]
    Fuse3(fuse3::MountImpl),
}

#[derive(Debug)]
pub(crate) struct Mount {
    backing: MountBacker,
    unmounted: bool,
}

impl Mount {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
    ) -> io::Result<(Arc<DevFuse>, Mount)> {
        #[cfg(fuser_mount_impl = "pure-rust")]
        {
            let (dev_fuse, mount) = fuse_pure::MountImpl::new(mountpoint, options)?;
            Ok((
                dev_fuse,
                Mount {
                    backing: MountBacker::Pure(mount),
                    unmounted: false,
                },
            ))
        }
        #[cfg(fuser_mount_impl = "libfuse2")]
        {
            let (dev_fuse, mount) = fuse2::MountImpl::new(mountpoint, options)?;
            Ok((
                dev_fuse,
                Mount {
                    backing: MountBacker::Fuse2(mount),
                    unmounted: false,
                },
            ))
        }
        #[cfg(fuser_mount_impl = "libfuse3")]
        {
            let (dev_fuse, mount) = fuse3::MountImpl::new(mountpoint, options)?;
            Ok((
                dev_fuse,
                Mount {
                    backing: MountBacker::Fuse3(mount),
                    unmounted: false,
                },
            ))
        }
        #[cfg(fuser_mount_impl = "macos-no-mount")]
        {
            let _ = (mountpoint, options);
            Err(io::Error::other(
                "Mount is not enabled; this is test-only configuration",
            ))
        }
    }

    fn umount_impl(&mut self, flags: &[UnmountOption]) -> io::Result<()> {
        if self.unmounted {
            return Ok(());
        }
        match &mut self.backing {
            #[cfg(fuser_mount_impl = "pure-rust")]
            MountBacker::Pure(mount) => mount.umount_impl(flags),
            #[cfg(fuser_mount_impl = "libfuse2")]
            MountBacker::Fuse2(mount) => mount.umount_impl(flags),
            #[cfg(fuser_mount_impl = "libfuse3")]
            MountBacker::Fuse3(mount) => mount.umount_impl(flags),
            // This branch is needed because Rust does not consider & empty enum non-empty.
            #[cfg(fuser_mount_impl = "internal-no-mount")]
            _ => Ok(()),
        }?;
        self.unmounted = true;
        Ok(())
    }

    pub(crate) fn umount(
        mut self,
        flags: &[UnmountOption],
    ) -> Result<(), (Option<Self>, io::Error)> {
        match unmount_options::check_option_conflicts(flags) {
            Ok(()) => (),
            Err(err) => return Err((Some(self), err)),
        };
        if let Err(err) = self.umount_impl(flags) {
            let salvaged = match err.raw_os_error() {
                Some(libc::EBUSY) => true,
                Some(libc::EAGAIN) => true,
                Some(libc::EFAULT) => false,
                Some(libc::EINVAL) => true,
                Some(libc::ENAMETOOLONG) => false,
                Some(libc::ENOENT) => false,
                Some(libc::ENOMEM) => true,
                Some(libc::EPERM) => true,
                _ => true,
            };
            return Err((salvaged.then_some(self), err));
        }
        Ok(())
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let drop_flags = {
            // Detached unmounts allows the mount to be removed immediately while still allowing the filesystems'
            // event loops to eventually terminate once the filesystem's reference count reaches zero.
            #[cfg(target_os = "linux")]
            {
                &[UnmountOption::Detach]
            }
            #[cfg(target_os = "macos")]
            {
                &[UnmountOption::Force]
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                &[]
            }
        };
        loop {
            match self.umount_impl(drop_flags) {
                Ok(()) => break,
                Err(err) => {
                    if err.raw_os_error() == Some(libc::EBUSY) {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        continue;
                    } else {
                        error!("Unmount failed: {}", err);
                    }
                }
            }
        }
    }
}

#[cfg_attr(fuser_mount_impl = "macos-no-mount", expect(dead_code))]
fn libc_umount(mnt: &CStr, flags: &[UnmountOption]) -> io::Result<()> {
    let nix_flags =
        nix::mount::MntFlags::from_bits_retain(unmount_options::to_unmount_syscall(flags));
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        nix::mount::unmount(mnt, nix_flags)?;
        Ok(())
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        nix::mount::umount2(mnt, nix_flags)?;
        Ok(())
    }
}

/// Warning: This will return true if the filesystem has been detached (lazy unmounted), but not
/// yet destroyed by the kernel.
#[cfg(any(test, fuser_mount_impl = "pure-rust"))]
fn is_mounted(fuse_device: &DevFuse) -> bool {
    use std::os::unix::io::AsFd;
    use std::slice;

    use nix::poll::PollFd;
    use nix::poll::PollFlags;
    use nix::poll::PollTimeout;
    use nix::poll::poll;

    loop {
        let mut poll_fd = PollFd::new(fuse_device.as_fd(), PollFlags::empty());
        let res = poll(slice::from_mut(&mut poll_fd), PollTimeout::ZERO);
        break match res {
            Ok(0) => true,
            Ok(1) => poll_fd
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLERR)),
            Ok(_) => unreachable!(),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(err) => {
                // This should never happen. The fd is guaranteed good as `File` owns it.
                // According to man poll ENOMEM is the only error code unhandled, so we panic
                // consistent with rust's usual ENOMEM behaviour.
                panic!("Poll failed with error {err}")
            }
        };
    }
}

#[cfg(test)]
mod test {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn fuse_args() {
        with_fuse_args(
            &[
                MountOption::CUSTOM("foo".into()),
                MountOption::CUSTOM("bar".into()),
            ],
            |args| {
                let v: Vec<_> = (0..args.argc)
                    .map(|n| unsafe {
                        CStr::from_ptr(*args.argv.offset(n as isize))
                            .to_str()
                            .unwrap()
                    })
                    .collect();
                assert_eq!(*v, ["rust-fuse", "-o", "foo", "-o", "bar"]);
            },
        );
    }
    fn cmd_mount() -> String {
        std::str::from_utf8(
            std::process::Command::new("sh")
                .arg("-c")
                .arg("mount | grep fuse")
                .output()
                .unwrap()
                .stdout
                .as_ref(),
        )
        .unwrap()
        .to_owned()
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn mount_unmount() {
        use std::mem::ManuallyDrop;

        // We use ManuallyDrop here to leak the directory on test failure.  We don't
        // want to try and clean up the directory if it's a mountpoint otherwise we'll
        // deadlock.
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let (file, mount) = Mount::new(tmp.path(), &[]).unwrap();
        let mnt = cmd_mount();
        eprintln!("Our mountpoint: {:?}\nfuse mounts:\n{}", tmp.path(), mnt,);
        assert!(mnt.contains(&*tmp.path().to_string_lossy()));
        assert!(is_mounted(&file));
        drop(mount);
        let mnt = cmd_mount();
        eprintln!("Our mountpoint: {:?}\nfuse mounts:\n{}", tmp.path(), mnt,);

        let detached = !mnt.contains(&*tmp.path().to_string_lossy());
        // Linux supports MNT_DETACH, so we expect unmount to succeed even if the FS
        // is busy.  Other systems don't so the unmount may fail and we will still
        // have the mount listed.  The mount will get cleaned up later.
        #[cfg(target_os = "linux")]
        assert!(detached);

        if detached {
            // We've detached successfully, it's safe to clean up:
            std::mem::ManuallyDrop::<_>::into_inner(tmp);
        }

        // Filesystem may have been lazy unmounted, so we can't assert this:
        // assert!(!is_mounted(&file));
    }
}
