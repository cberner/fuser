//! `auto_unmount` needs something that outlives the mounting process to do the unmount.
//! Where neither a mount helper nor the privilege to mount directly is available, the
//! error has to say that the option is what asked for them: mounting without it may well
//! work, and nothing else points that out (issue #283).
//!
//! This is a test binary of its own because it sets `FUSERMOUNT_PATH`, which the whole
//! process sees, and which is only sound to set before any second thread exists.

#![cfg(fuser_mount_impl = "pure-rust")]

use fuser::Config;
use fuser::Filesystem;
use fuser::MountOption;
use fuser::Session;
use fuser::SessionACL;

struct NullFs;
impl Filesystem for NullFs {}

#[test]
fn auto_unmount_names_itself_when_the_mount_helper_cannot_run() {
    // SAFETY: the only test in this binary, so nothing else is running yet
    unsafe { std::env::set_var("FUSERMOUNT_PATH", "/nonexistent/fusermount") };

    let tmp = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.mount_options = vec![MountOption::AutoUnmount];
    config.acl = SessionACL::All;

    let err = Session::new(NullFs, tmp.path(), &config)
        .err()
        .expect("mounting must fail when the configured mount helper cannot be run");
    let message = err.to_string();
    assert!(
        message.contains("auto_unmount"),
        "the error must name the option that needed the helper: {message}"
    );
    assert!(
        message.contains("/nonexistent/fusermount"),
        "the error must name the helper it could not run: {message}"
    );
}
