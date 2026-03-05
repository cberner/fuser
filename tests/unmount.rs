mod fixtures;

use std::io::Read;
use std::time::Duration;

use fixtures::hello_fs::HelloFS;
use fuser::Config;
use fuser::MountOption;
use fuser::SessionACL;

#[test_log::test]
fn should_prompt_unmount_retry_while_file_is_open_without_autounmount() {
    let mut mountpoint = tempfile::tempdir().unwrap();
    mountpoint.disable_cleanup(true);
    let mut cfg = Config::default();
    cfg.acl = SessionACL::RootAndOwner;
    cfg.n_threads = Some(2);
    let session = fuser::spawn_mount(HelloFS, &mountpoint, &cfg).unwrap();
    let hello_file = mountpoint.path().join("hello.txt");

    let (handle_open_done_tx, handle_open_done_rx) = std::sync::mpsc::channel::<()>();
    let (umount_completed_tx, unmount_completed_rx) = std::sync::mpsc::channel::<()>();

    let main_thread = std::thread::spawn(move || {
        // Attempt to unmount while the file is open
        handle_open_done_rx.recv().expect("recv handle open done");
        // TODO: the outstanding handle must be closed for the unmount to finish, for which the thread owning the outstanding
        // handle must receive a message from umount_and_join that it would fail with EBUSY (otherwise, the outstanding
        // handle might be closed before an unmount is attempted, which causes the unmount to succeed immediately and
        // makes the test flaky). The only way to mitigate the flakiness without non-blocking cooperation from umount_and_join
        // is to make the handle thread wait for some time.

        // In previous candidate PRs, this is done by creating an interface that does not perform a lazy/detach
        // unmount, which returns EBUSY, allowing the thread to send a signal to the thread owning the outstanding
        // handle to inform it that it cannot unmount.
        session.umount_and_join().expect("unmount should succeed");
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
        // FIXME: this part should have waited for the main thread to send a busy/blocking error
        std::thread::sleep(Duration::from_secs_f64(0.25));
        drop(file);
    });

    let res = unmount_completed_rx.recv_timeout(Duration::from_secs(5));
    if let Err(e) = res {
        let _ = main_thread.join();
        let _ = hello_thread.join();
        panic!("unmount completed rx error: {:?}", e);
    }
    main_thread.join().expect("join main thread");
    hello_thread.join().expect("join hello thread");
}

#[test_log::test]
fn should_prompt_unmount_retry_while_file_is_open_with_autounmount() {
    let mut mountpoint = tempfile::tempdir().unwrap();
    mountpoint.disable_cleanup(true);
    let mut cfg = Config::default();
    cfg.acl = SessionACL::RootAndOwner;
    cfg.n_threads = Some(2);
    cfg.mount_options.push(MountOption::AutoUnmount);
    let session = fuser::spawn_mount(HelloFS, &mountpoint, &cfg).unwrap();
    let hello_file = mountpoint.path().join("hello.txt");

    let (handle_open_done_tx, handle_open_done_rx) = std::sync::mpsc::channel::<()>();
    let (umount_completed_tx, unmount_completed_rx) = std::sync::mpsc::channel::<()>();

    let main_thread = std::thread::spawn(move || {
        // Attempt to unmount while the file is open
        handle_open_done_rx.recv().expect("recv handle open done");
        // TODO: the outstanding handle must be closed for the unmount to finish, for which the thread owning the outstanding
        // handle must receive a message from umount_and_join that it would fail with EBUSY (otherwise, the outstanding
        // handle might be closed before an unmount is attempted, which causes the unmount to succeed immediately and
        // makes the test flaky). The only way to mitigate the flakiness without non-blocking cooperation from umount_and_join
        // is to make the handle thread wait for some time.

        // In previous candidate PRs, this is done by creating an interface that does not perform a lazy/detach
        // unmount, which returns EBUSY, allowing the thread to send a signal to the thread owning the outstanding
        // handle to inform it that it cannot unmount.
        session.umount_and_join().expect("unmount should succeed");
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
        // FIXME: this part should have waited for the main thread to send a busy/blocking error
        std::thread::sleep(Duration::from_secs_f64(0.25));
        drop(file);
    });

    let res = unmount_completed_rx.recv_timeout(Duration::from_secs(5));
    if let Err(e) = res {
        let _ = main_thread.join();
        let _ = hello_thread.join();
        panic!("unmount completed rx error: {:?}", e);
    }
    main_thread.join().expect("join main thread");
    hello_thread.join().expect("join hello thread");
}
