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

use std::io;

#[cfg(any(test, fuser_mount_impl = "libfuse2", fuser_mount_impl = "libfuse3"))]
use fuse2_sys::fuse_args;
use mount_options::MountOption;

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
pub(crate) enum Mount {
    #[cfg(fuser_mount_impl = "pure-rust")]
    Pure(
        #[expect(dead_code)] // Is held for drop.
        fuse_pure::Mount,
    ),
    #[cfg(fuser_mount_impl = "libfuse2")]
    Fuse2(
        #[expect(dead_code)] // Is held for drop.
        fuse2::Mount,
    ),
    #[cfg(fuser_mount_impl = "libfuse3")]
    Fuse3(
        #[expect(dead_code)] // Is held for drop.
        fuse3::Mount,
    ),
}

impl Mount {
    #[allow(unreachable_code)]
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
    ) -> io::Result<(Arc<DevFuse>, Mount)> {
        #[cfg(fuser_mount_impl = "pure-rust")]
        {
            let (dev_fuse, mount) = fuse_pure::Mount::new(mountpoint, options)?;
            Ok((dev_fuse, Mount::Pure(mount)))
        }
        #[cfg(fuser_mount_impl = "libfuse2")]
        {
            let (dev_fuse, mount) = fuse2::Mount::new(mountpoint, options)?;
            Ok((dev_fuse, Mount::Fuse2(mount)))
        }
        #[cfg(fuser_mount_impl = "libfuse3")]
        {
            let (dev_fuse, mount) = fuse3::Mount::new(mountpoint, options)?;
            Ok((dev_fuse, Mount::Fuse3(mount)))
        }
        #[cfg(fuser_mount_impl = "internal-no-mount")]
        {
            let _ = (mountpoint, options);
            Err(io::Error::other(
                "Mount is not enabled; this is test-only configuration",
            ))
        }
    }
}

#[cfg_attr(fuser_mount_impl = "internal-no-mount", expect(dead_code))]
fn libc_umount(mnt: &CStr) -> io::Result<()> {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        nix::mount::unmount(mnt, nix::mount::MntFlags::empty())?;
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
        nix::mount::umount(mnt)?;
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
