use fuser::{Filesystem, Mount, Session};
use std::rc::Rc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

#[test]
#[cfg(target_os = "linux")]
fn unmount_no_send() {
    // Rc to make this !Send
    struct NoSendFS(Rc<()>);

    impl Filesystem for NoSendFS {}

    let tmpdir: TempDir = tempfile::tempdir().unwrap();

    let (device_fd, mount) = Mount::new_fusermount(tmpdir.path(), &[]).expect("failed to mount");
    let mut session = Session::from_fd(device_fd, NoSendFS(Rc::new(())), fuser::SessionACL::Owner);

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        drop(mount);
    });

    session.run().unwrap();
}
