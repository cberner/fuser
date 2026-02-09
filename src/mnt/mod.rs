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

#[cfg(not(fuser_mount_impl = "macos-no-mount"))]
mod fusermount;

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
fn with_fuse_args<T, F: FnOnce(&mut fuse_args) -> T>(
    options: &[MountOption],
    acl: SessionACL,
    f: F,
) -> T {
    use std::ffi::CString;

    use mount_options::option_to_string;

    let mut args = vec![CString::new("rust-fuse").unwrap()];
    for x in options {
        args.extend_from_slice(&[
            CString::new("-o").unwrap(),
            CString::new(option_to_string(x)).unwrap(),
        ]);
    }
    if let Some(acl) = acl.to_mount_option() {
        args.push(CString::new("-o").unwrap());
        args.push(CString::new(acl).unwrap());
    }
    let argptrs: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
    f(&mut fuse_args {
        argc: argptrs.len() as i32,
        argv: argptrs.as_ptr(),
        allocated: 0,
    })
}

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use crate::SessionACL;

#[derive(Debug)]
enum MountImpl {
    #[cfg(fuser_mount_impl = "pure-rust")]
    Pure(fuse_pure::MountImpl),
    #[cfg(fuser_mount_impl = "libfuse2")]
    Fuse2(fuse2::MountImpl),
    #[cfg(fuser_mount_impl = "libfuse3")]
    Fuse3(fuse3::MountImpl),
}

impl MountImpl {
    fn is_alive(&self) -> bool {
        match self {
            #[cfg(fuser_mount_impl = "pure-rust")]
            MountImpl::Pure(mount) => mount.is_alive(),
            #[cfg(fuser_mount_impl = "libfuse2")]
            MountImpl::Fuse2(mount) => mount.is_alive(),
            #[cfg(fuser_mount_impl = "libfuse3")]
            MountImpl::Fuse3(mount) => mount.is_alive(),
            // This branch is needed because Rust does not consider & empty enum non-empty.
            #[cfg(fuser_mount_impl = "macos-no-mount")]
            _ => false,
        }
    }

    fn umount_impl(&mut self, _flags: &[UnmountOption]) -> io::Result<()> {
        match self {
            #[cfg(fuser_mount_impl = "pure-rust")]
            MountImpl::Pure(mount) => mount.umount_impl(_flags),
            #[cfg(fuser_mount_impl = "libfuse2")]
            MountImpl::Fuse2(mount) => mount.umount_impl(_flags),
            #[cfg(fuser_mount_impl = "libfuse3")]
            MountImpl::Fuse3(mount) => mount.umount_impl(_flags),
            // This branch is needed because Rust does not consider & empty enum non-empty.
            #[cfg(fuser_mount_impl = "macos-no-mount")]
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Mount {
    mount_impl: Option<MountImpl>,
    #[allow(dead_code)]
    mount_point: PathBuf,
}

impl Mount {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, Mount)> {
        #[cfg(fuser_mount_impl = "pure-rust")]
        {
            let (dev_fuse, mount) = fuse_pure::MountImpl::new(mountpoint, options, acl)?;
            Ok((
                dev_fuse,
                Mount {
                    mount_impl: Some(MountImpl::Pure(mount)),
                    mount_point: mountpoint.to_path_buf(),
                },
            ))
        }
        #[cfg(fuser_mount_impl = "libfuse2")]
        {
            let (dev_fuse, mount) = fuse2::MountImpl::new(mountpoint, options, acl)?;
            Ok((
                dev_fuse,
                Mount {
                    mount_impl: Some(MountImpl::Fuse2(mount)),
                    mount_point: mountpoint.to_path_buf(),
                },
            ))
        }
        #[cfg(fuser_mount_impl = "libfuse3")]
        {
            let (dev_fuse, mount) = fuse3::MountImpl::new(mountpoint, options, acl)?;
            Ok((
                dev_fuse,
                Mount {
                    mount_impl: Some(MountImpl::Fuse3(mount)),
                    mount_point: mountpoint.to_path_buf(),
                },
            ))
        }
        #[cfg(fuser_mount_impl = "macos-no-mount")]
        {
            let _ = (mountpoint, options, acl);
            Err(io::Error::other(
                "Mount is not enabled; this is test-only configuration",
            ))
        }
    }

    pub(crate) fn umount(
        mut self,
        flags: &[UnmountOption],
    ) -> Result<(), (Option<Self>, io::Error)> {
        let mount_impl = match self.mount_impl.as_mut() {
            Some(mount) => mount,
            None => return Ok(()),
        };
        match unmount_options::check_option_conflicts(flags) {
            Ok(()) => (),
            Err(err) => return Err((Some(self), err)),
        };
        if let Err(err) = mount_impl.umount_impl(flags) {
            let salvaged = is_mount_salvageable(&err) && mount_impl.is_alive();
            if !salvaged {
                self.mount_impl = None;
            }
            return Err((salvaged.then_some(self), err));
        }
        // This prevents the mount from being removed twice.
        self.mount_impl = None;
        Ok(())
    }
}

pub(crate) fn drop_umount_flags() -> &'static [UnmountOption] {
    {
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
    }
}

pub(crate) fn with_retry_on_busy_or_again(mut f: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    loop {
        match f() {
            Ok(()) => return Ok(()),
            Err(err) => {
                let err_kind = err.kind();
                if err_kind == io::ErrorKind::ResourceBusy {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                } else if err_kind == io::ErrorKind::WouldBlock {
                    std::thread::sleep(std::time::Duration::from_secs_f64(0.01));
                } else {
                    return Err(err);
                }
            }
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let drop_flags = drop_umount_flags();
        if let Some(mount_impl) = self.mount_impl.as_mut() {
            match with_retry_on_busy_or_again(|| mount_impl.umount_impl(drop_flags)) {
                Ok(()) => (),
                Err(err) => {
                    // This is a fallback when DETACH is not supported.
                    error!("Unmount failed: {}", err);
                }
            }
        }
    }
}

#[cfg_attr(fuser_mount_impl = "macos-no-mount", expect(dead_code))]
fn libc_umount(mnt: &Path, flags: &[UnmountOption]) -> nix::Result<()> {
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

/// Determines whether a mount can be salvaged after an error.
fn is_mount_salvageable(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::ResourceBusy => return true,
        io::ErrorKind::WouldBlock => return true,
        io::ErrorKind::InvalidInput => return false,
        io::ErrorKind::PermissionDenied => return true,
        io::ErrorKind::NotFound => return false,
        io::ErrorKind::OutOfMemory => return true,
        _ => {}
    };
    match err.raw_os_error() {
        Some(libc::EBUSY) => true,
        Some(libc::EAGAIN) => true,
        Some(libc::EFAULT) => false,
        Some(libc::EINVAL) => false,
        Some(libc::ENAMETOOLONG) => false,
        Some(libc::ENOENT) => true,
        Some(libc::ENOMEM) => true,
        Some(libc::EPERM) => true,
        _ => false,
    }
}

/// Warning: This will return true if the filesystem has been detached (lazy unmounted), but not
/// yet destroyed by the kernel.
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

    use crate::mnt::*;

    #[test]
    fn fuse_args() {
        with_fuse_args(
            &[
                MountOption::CUSTOM("foo".into()),
                MountOption::CUSTOM("bar".into()),
            ],
            SessionACL::RootAndOwner,
            |args| {
                let v: Vec<_> = (0..args.argc)
                    .map(|n| unsafe {
                        CStr::from_ptr(*args.argv.offset(n as isize))
                            .to_str()
                            .unwrap()
                    })
                    .collect();
                assert_eq!(
                    *v,
                    ["rust-fuse", "-o", "foo", "-o", "bar", "-o", "allow_other"]
                );
            },
        );
    }

    #[cfg(not(target_os = "macos"))]
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
        let (file, mount) = Mount::new(tmp.path(), &[], SessionACL::default()).unwrap();
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
