use std::{io::Read, time::Duration};
mod fixtures;

#[test]
fn test_unmount_while_file_is_open() {
    let mountpoint = tempfile::tempdir().unwrap();
    let session = fuser::spawn_mount2(
        fixtures::hello_fs::HelloFS,
        &mountpoint,
        &[
            fuser::MountOption::AutoUnmount,
            fuser::MountOption::AllowOther,
        ],
    )
    .unwrap();
    let hello_file = mountpoint.path().join("hello.txt");

    let (handle_open_done_tx, handle_open_done_rx) = std::sync::mpsc::channel::<()>();
    let (unmount_error_done_tx, unmount_error_done_rx) = std::sync::mpsc::channel::<()>();
    let (handle_close_done_tx, handle_close_done_rx) = std::sync::mpsc::channel::<()>();
    let (umount_completed_tx, unmount_completed_rx) = std::sync::mpsc::channel::<()>();

    let session_thread = std::thread::spawn(move || {
        // Attempt to unmount while the file is open
        handle_open_done_rx.recv().expect("recv handle open done");
        let (session, error) = session
            .umount_and_join(&[])
            .expect_err("unmount should fail");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ResourceBusy,
            "unmount should fail with ResourceBusy because the file is opened"
        );
        // Notify that the unmount attempt is done, file thread can close the file
        unmount_error_done_tx
            .send(())
            .expect("send unmount error done");
        // Wait for the hello thread to finish closing the file
        handle_close_done_rx.recv().expect("recv handle close done");
        session
            .expect("session should still be valid")
            .umount_and_join(&[])
            .expect("unmount should succeed now that the file handle is closed");
        // Notify that unmount succeeded and test case should finish
        umount_completed_tx
            .send(())
            .expect("send unmount completed");
    });
    let hello_thread = std::thread::spawn(move || {
        let mut file = std::fs::File::open(hello_file).expect("open hello file");
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).expect("read hello file");
        // Notify the main thread that the file is opened - the session should try to unmount while the handle is open
        handle_open_done_tx.send(()).expect("send handle open done");
        // Wait for the main thread to send an error
        unmount_error_done_rx
            .recv()
            .expect("recv unmount error done");
        drop(file);
        // The file is dropped, so the session should be able to unmount
        handle_close_done_tx
            .send(())
            .expect("send handle close done");
    });

    unmount_completed_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("test case should finish within 10 seconds, something might be blocking the unmount process");
    session_thread.join().expect("join session thread");
    hello_thread.join().expect("join hello thread");
}
