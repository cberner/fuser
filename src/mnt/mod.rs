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
use log::info;
use log::warn;
use mount_options::MountOption;
use mount_options::check_option_values;

use crate::dev_fuse::DevFuse;

/// Helper function to provide options as a `fuse_args` struct
/// (which contains an argc count and an argv pointer)
#[cfg(any(test, fuser_mount_impl = "libfuse2", fuser_mount_impl = "libfuse3"))]
fn with_fuse_args<T, F: FnOnce(&fuse_args) -> T>(
    options: &[MountOption],
    acl: SessionACL,
    f: F,
) -> T {
    use std::ffi::CString;

    use mount_options::option_to_escaped_string;

    let mut args = vec![CString::new("rust-fuse").unwrap()];
    for x in options {
        args.extend_from_slice(&[
            CString::new("-o").unwrap(),
            CString::new(option_to_escaped_string(x))
                .expect("option values are checked for NUL by check_option_values()"),
        ]);
    }
    if let Some(acl) = acl.to_mount_option() {
        args.push(CString::new("-o").unwrap());
        args.push(CString::new(acl).unwrap());
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
    fn umount_impl(&mut self) -> io::Result<()> {
        match self {
            #[cfg(fuser_mount_impl = "pure-rust")]
            MountImpl::Pure(mount) => mount.umount_impl(),
            #[cfg(fuser_mount_impl = "libfuse2")]
            MountImpl::Fuse2(mount) => mount.umount_impl(),
            #[cfg(fuser_mount_impl = "libfuse3")]
            MountImpl::Fuse3(mount) => mount.umount_impl(),
            // This branch is needed because Rust does not consider & empty enum non-empty.
            #[cfg(fuser_mount_impl = "macos-no-mount")]
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Mount {
    mount_impl: Option<MountImpl>,
    mount_point: PathBuf,
    /// The FUSE device fd of this mount's kernel connection.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fuse_device: Arc<DevFuse>,
}

impl Mount {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, Mount)> {
        // Checked here, rather than in Session, so that every formatting of an option
        // value below can rely on it
        check_option_values(options)?;

        #[cfg(fuser_mount_impl = "pure-rust")]
        let (dev_fuse, mount_impl) = {
            let (dev_fuse, mount) = fuse_pure::MountImpl::new(mountpoint, options, acl)?;
            (dev_fuse, MountImpl::Pure(mount))
        };
        #[cfg(fuser_mount_impl = "libfuse2")]
        let (dev_fuse, mount_impl) = {
            let (dev_fuse, mount) = fuse2::MountImpl::new(mountpoint, options, acl)?;
            (dev_fuse, MountImpl::Fuse2(mount))
        };
        #[cfg(fuser_mount_impl = "libfuse3")]
        let (dev_fuse, mount_impl) = {
            let (dev_fuse, mount) = fuse3::MountImpl::new(mountpoint, options, acl)?;
            (dev_fuse, MountImpl::Fuse3(mount))
        };
        #[cfg(fuser_mount_impl = "macos-no-mount")]
        {
            let _ = (mountpoint, options, acl);
            Err(io::Error::other(
                "Mount is not enabled; this is test-only configuration",
            ))
        }
        #[cfg(not(fuser_mount_impl = "macos-no-mount"))]
        {
            Ok((
                dev_fuse.clone(),
                Mount {
                    mount_impl: Some(mount_impl),
                    mount_point: mountpoint.to_path_buf(),
                    fuse_device: dev_fuse,
                },
            ))
        }
    }

    /// Whether teardown should unmount the mountpoint: only if our kernel connection
    /// is still alive. If it is dead (POLLERR on the FUSE device fd), the filesystem
    /// was either unmounted externally (issue #658) or the connection was aborted,
    /// and unmounting by path could hit an unrelated filesystem mounted there in the
    /// meantime. This is the same check libfuse's fuse_kern_unmount() performs, with
    /// the same limits: an aborted connection whose dead mount is still in the mount
    /// table is left behind (auto_unmount or "fusermount -u -z" cleans it up), and a
    /// lazily detached mount keeps the connection alive, so it is still unmounted by
    /// path. The decision never accesses the mountpoint through the filesystem,
    /// which could block on an unresponsive or unserved mount.
    #[cfg(not(target_os = "macos"))]
    fn should_unmount(&self) -> bool {
        is_mounted(&self.fuse_device)
    }

    #[cfg(target_os = "macos")]
    fn should_unmount(&self) -> bool {
        true
    }

    pub(crate) fn umount(mut self) -> io::Result<()> {
        match self.mount_impl.take() {
            Some(mut mount) => {
                if !self.should_unmount() {
                    return Ok(());
                }
                info!("Unmounting {}", self.mount_point.display());
                mount.umount_impl()
            }
            None => Ok(()),
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if let Some(mut mount) = self.mount_impl.take() {
            if !self.should_unmount() {
                return;
            }
            if let Err(err) = mount.umount_impl() {
                // This is not necessarily an error: may happen if a user called 'umount'.
                warn!("Unmount failed: {}", err);
            }
        }
    }
}

#[cfg_attr(fuser_mount_impl = "macos-no-mount", expect(dead_code))]
fn libc_umount(mnt: &CStr) -> nix::Result<()> {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        nix::mount::unmount(mnt, nix::mount::MntFlags::empty())
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        nix::mount::umount(mnt)
    }
}

/// Waits (bounded) for the FUSE kernel connection to end after an unmount was
/// requested. Returns false if the connection is still alive when the timeout
/// expires, e.g. because a lazily unmounted filesystem is still in use, or an
/// unmount helper failed in a way that cannot be observed directly.
#[cfg(not(target_os = "macos"))]
pub(crate) fn connection_ended(fuse_device: &DevFuse, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while is_mounted(fuse_device) {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    true
}

/// The FUSE device poll semantics are untested on macOS, so assume the unmount
/// took effect there.
#[cfg(target_os = "macos")]
pub(crate) fn connection_ended(_fuse_device: &DevFuse, _timeout: std::time::Duration) -> bool {
    true
}

/// Lazily unmount via the given fusermount binary. Helper failures are reported,
/// so that callers do not mistake a still-mounted filesystem for an unmounted
/// one - BackgroundSession would otherwise wait forever for the session to end.
#[cfg(any(
    all(test, target_os = "linux"),
    fuser_mount_impl = "pure-rust",
    all(
        fuser_mount_impl = "libfuse2",
        not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        ))
    )
))]
pub(crate) fn fusermount_unmount(fusermount_bin: &str, mountpoint: &CStr) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    use log::debug;

    let mut builder = std::process::Command::new(fusermount_bin);
    builder
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    builder
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(std::ffi::OsStr::from_bytes(mountpoint.to_bytes()));

    let output = builder.output()?;
    debug!("fusermount: {}", String::from_utf8_lossy(&output.stdout));
    debug!("fusermount: {}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "fusermount failed to unmount ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Warning: This will return true if the filesystem has been detached (lazy unmounted), but not
/// yet destroyed by the kernel.
#[cfg(not(target_os = "macos"))]
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
            // The kernel reports POLLERR on /dev/fuse if and only if the connection
            // is no longer alive, i.e. the filesystem has been unmounted or aborted
            Ok(1) => !poll_fd
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

    /// A fusermount helper that cannot run or exits nonzero must report an error:
    /// the filesystem is then still mounted, and treating that as success would
    /// make teardown wait forever for a session that never ends.
    #[test]
    #[cfg(target_os = "linux")]
    fn fusermount_unmount_reports_failure() {
        use std::ffi::CString;

        let mountpoint = CString::new("/nonexistent").unwrap();
        // Helper exits nonzero (/bin/false ignores its arguments)
        assert!(fusermount_unmount("/bin/false", &mountpoint).is_err());
        // Helper cannot be executed at all
        assert!(fusermount_unmount("/nonexistent/fusermount", &mountpoint).is_err());
        // Helper reports success
        assert!(fusermount_unmount("/bin/true", &mountpoint).is_ok());
    }

    /// libfuse splits each -o argument on commas, so a comma in a value must reach it
    /// escaped
    #[test]
    fn fuse_args_escaping() {
        with_fuse_args(
            &[MountOption::FSName("foo,ro".into())],
            SessionACL::Owner,
            |args| {
                let v: Vec<_> = (0..args.argc)
                    .map(|n| unsafe {
                        CStr::from_ptr(*args.argv.offset(n as isize))
                            .to_str()
                            .unwrap()
                    })
                    .collect();
                assert_eq!(*v, ["rust-fuse", "-o", "fsname=foo\\,ro"]);
            },
        );
    }

    /// A comma in `FSName` must end up in the source name of the mount, rather than
    /// being interpreted as a separate mount option
    #[test]
    #[cfg(target_os = "linux")]
    fn mount_unmount_fsname_with_comma() {
        use std::mem::ManuallyDrop;

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let options = [MountOption::FSName("fuser,ro".to_owned())];
        let (_file, mount) = Mount::new(tmp.path(), &options, SessionACL::default()).unwrap();

        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        let fields: Vec<&str> = mounts
            .lines()
            .map(|line| line.split(' ').collect::<Vec<_>>())
            .find(|fields| fields[1] == tmp.path().to_str().unwrap())
            .unwrap_or_else(|| panic!("{:?} not found in:\n{}", tmp.path(), mounts));
        assert_eq!(fields[0], "fuser,ro");
        assert!(
            !fields[3].split(',').any(|option| option == "ro"),
            "the comma in the source name leaked into the mount options: {}",
            fields[3]
        );

        mount.umount().unwrap();
        ManuallyDrop::into_inner(tmp);
    }

    /// A NUL in an option value must be reported as an error, rather than panicking
    #[test]
    fn mount_option_with_nul() {
        let tmp = tempfile::tempdir().unwrap();
        let options = [MountOption::FSName("no\0name".to_owned())];
        let err = Mount::new(tmp.path(), &options, SessionACL::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
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

    /// After the filesystem is unmounted by an external process (e.g. a user
    /// running 'umount'), `is_mounted()` must report false so that session
    /// teardown does not attempt a second unmount of the mountpoint.
    ///
    /// The `mount_unmount` name prefix keeps this test covered by the
    /// `--skip=mnt::test::mount_unmount` filter used on platforms where
    /// unprivileged mounting is unavailable.
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn mount_unmount_external() {
        use std::mem::ManuallyDrop;

        // We use ManuallyDrop here to leak the directory on test failure.  We don't
        // want to try and clean up the directory if it's a mountpoint otherwise we'll
        // deadlock.
        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let (file, mount) = Mount::new(tmp.path(), &[], SessionACL::default()).unwrap();
        assert!(is_mounted(&file));

        external_unmount(tmp.path());
        wait_until_not_mounted(&file);

        // Unmounting again must succeed as a no-op now that the filesystem is
        // already gone, on every mount backend (issue #658: the libfuse backends
        // used to fail with EINVAL here and log a spurious warning)
        mount
            .umount()
            .expect("unmount after external unmount must succeed");
        ManuallyDrop::into_inner(tmp);
    }

    /// After an external unmount, an unrelated replacement filesystem mounted at the
    /// same path must not be unmounted by the old session's teardown, nor may teardown
    /// probe the mountpoint through the (unserved) replacement filesystem, which would
    /// block indefinitely.
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn mount_unmount_replacement() {
        use std::mem::ManuallyDrop;

        let tmp = ManuallyDrop::new(tempfile::tempdir().unwrap());
        let (file_a, mount_a) = Mount::new(tmp.path(), &[], SessionACL::default()).unwrap();
        assert!(is_mounted(&file_a));

        external_unmount(tmp.path());
        wait_until_not_mounted(&file_a);

        // Mount an unrelated replacement filesystem at the same path. Nothing serves
        // it, so any teardown path that touches the mountpoint via the filesystem
        // would block
        let (file_b, mount_b) = Mount::new(tmp.path(), &[], SessionACL::default()).unwrap();
        assert!(is_mounted(&file_b));

        mount_a
            .umount()
            .expect("unmount after external unmount must succeed");
        assert!(
            is_mounted(&file_b),
            "teardown of the old session must not unmount the replacement filesystem"
        );

        mount_b.umount().expect("replacement unmount must succeed");
        ManuallyDrop::into_inner(tmp);
    }

    /// Unmount externally, without going through `Mount`
    #[cfg(not(target_os = "macos"))]
    fn external_unmount(mountpoint: &std::path::Path) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let unmounted = ["fusermount3", "fusermount"].iter().any(|bin| {
            std::process::Command::new(bin)
                .arg("-u")
                .arg(mountpoint)
                .status()
                .is_ok_and(|status| status.success())
        });
        if !unmounted {
            // No fusermount binary available; fall back to umount(2), which
            // requires root
            let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
            libc_umount(&mountpoint).unwrap();
        }
    }

    /// The kernel may tear the connection down asynchronously, so allow some time
    #[cfg(not(target_os = "macos"))]
    fn wait_until_not_mounted(file: &Arc<DevFuse>) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while is_mounted(file) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !is_mounted(file),
            "connection must be dead after the filesystem was unmounted"
        );
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
