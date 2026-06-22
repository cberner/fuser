use fuser::{Config, MountOption, SessionACL};

mod fixtures;

/// # Scenario
/// In unpatched versions of `fuser`, if auto_unmount is on, the library relies exclusively on dropping the socket to unmount. The `fusermount` daemon will then request a [directory open](https://github.com/libfuse/libfuse/blob/07a1b913b180627db5e9659e31a86c68637a9308/util/fusermount.c#L1544-L1560) in `should_auto_unmount`. In short, auto_unmount only triggers an unmount if the FUSE device is closed.
/// - If the FUSE handler does not respond, the unmounting process will hang.
/// - In the more likely case where the FUSE handler does respond and return a directory handle or anything other than [`fuser::Errno::ENOTCONN`], `should_auto_unmount` will return `false(0)` and the `fusermount` process exits without doing any unmounting.
///
/// # Notes
/// SimpleFS fixture is used to emulate FUSE requests.
#[cfg(target_os = "linux")]
#[test_log::test]
fn test_session_auto_unmount() {
    let data_dir = tempfile::TempDir::new().unwrap();
    let mountpoint = tempfile::TempDir::new().unwrap();
    let filesystem =
        fixtures::simple::SimpleFS::new(data_dir.path().to_str().unwrap().to_string(), false, true);
    let mut config = Config::default();
    config.mount_options.extend(vec![
        MountOption::AutoUnmount,
        MountOption::FSName("fuser".to_string()),
    ]);
    config.n_threads = Some(2);
    config.acl = SessionACL::All;
    let session = fuser::spawn_mount(filesystem, mountpoint, &config).unwrap();
    session.umount_and_join().expect("Failed to unmount");
}
