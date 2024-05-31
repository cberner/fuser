use fuser::{Filesystem, Session};
use std::rc::Rc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unmount_no_send() {
    // Rc to make this !Send
    env_logger::init();
    struct NoSendFS(Rc<()>);

    impl Filesystem for NoSendFS {}

    let tmpdir: TempDir = tempfile::tempdir().unwrap();
    let mut session = Session::new(NoSendFS(Rc::new(())), tmpdir.path(), &[]).unwrap();
    log::debug!("Session created");
    let mut unmounter = session.unmount_callable();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        log::debug!("unmounting");
        unmounter.unmount().unwrap();
        log::debug!("unmounted");
    });
    log::debug!("running session");
    session.run().unwrap();
    log::debug!("session finished")
}
