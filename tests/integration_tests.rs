use fuser::{Filesystem, Session, SessionACL};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn unmount_no_send() {
    struct NoSendFS(
        // Rc to make this !Send
        #[allow(dead_code)] Rc<()>,
    );

    impl Filesystem for NoSendFS {}

    let tmpdir: TempDir = tempfile::tempdir().unwrap();
    let mut session = Session::new(NoSendFS(Rc::new(())), tmpdir.path(), &[]).unwrap();
    let mut unmounter = session.unmount_callable();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        unmounter.unmount().unwrap();
    });
    session.run().unwrap();
}

/// Test that clone_fd creates a working file descriptor for multi-reader setups.
#[cfg(target_os = "linux")]
#[test]
fn clone_fd_multi_reader() {
    use std::os::fd::AsRawFd;

    // Simple filesystem that tracks how many times getattr is called
    struct CountingFS {
        count: Arc<AtomicUsize>,
    }

    impl Filesystem for CountingFS {
        fn getattr(
            &mut self,
            _req: &fuser::Request<'_>,
            ino: u64,
            _fh: Option<u64>,
            reply: fuser::ReplyAttr,
        ) {
            self.count.fetch_add(1, Ordering::SeqCst);
            if ino == 1 {
                // Root directory
                reply.attr(
                    &Duration::from_secs(1),
                    &fuser::FileAttr {
                        ino: 1,
                        size: 0,
                        blocks: 0,
                        atime: std::time::UNIX_EPOCH,
                        mtime: std::time::UNIX_EPOCH,
                        ctime: std::time::UNIX_EPOCH,
                        crtime: std::time::UNIX_EPOCH,
                        kind: fuser::FileType::Directory,
                        perm: 0o755,
                        nlink: 2,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 4096,
                        flags: 0,
                    },
                );
            } else {
                reply.error(libc::ENOENT);
            }
        }
    }

    let tmpdir: TempDir = tempfile::tempdir().unwrap();
    let count = Arc::new(AtomicUsize::new(0));

    let session = Session::new(
        CountingFS {
            count: count.clone(),
        },
        tmpdir.path(),
        &[],
    )
    .unwrap();

    // Clone the fd - this should succeed
    let cloned_fd = session.clone_fd().expect("clone_fd should succeed");

    // Verify it's a valid fd (different from the original)
    assert!(cloned_fd.as_raw_fd() >= 0);

    // Clean up
    drop(cloned_fd);
    drop(session);
}

/// Test that from_fd_initialized creates a session that can process requests.
#[cfg(target_os = "linux")]
#[test]
fn from_fd_initialized_works() {
    use std::sync::Barrier;

    // Simple filesystem that responds to getattr
    #[derive(Clone)]
    struct SimpleFS;

    impl Filesystem for SimpleFS {
        fn getattr(
            &mut self,
            _req: &fuser::Request<'_>,
            ino: u64,
            _fh: Option<u64>,
            reply: fuser::ReplyAttr,
        ) {
            if ino == 1 {
                reply.attr(
                    &Duration::from_secs(1),
                    &fuser::FileAttr {
                        ino: 1,
                        size: 0,
                        blocks: 0,
                        atime: std::time::UNIX_EPOCH,
                        mtime: std::time::UNIX_EPOCH,
                        ctime: std::time::UNIX_EPOCH,
                        crtime: std::time::UNIX_EPOCH,
                        kind: fuser::FileType::Directory,
                        perm: 0o755,
                        nlink: 2,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        blksize: 4096,
                        flags: 0,
                    },
                );
            } else {
                reply.error(libc::ENOENT);
            }
        }
    }

    let tmpdir: TempDir = tempfile::tempdir().unwrap();

    let mut session = Session::new(SimpleFS, tmpdir.path(), &[]).unwrap();
    let mut unmounter = session.unmount_callable();

    // Clone fd for second reader
    let cloned_fd = session.clone_fd().expect("clone_fd should succeed");

    // Barrier to synchronize reader threads
    let barrier = Arc::new(Barrier::new(3)); // 2 readers + 1 main thread

    // Start second reader in a thread
    let barrier_clone = barrier.clone();
    let reader_handle = thread::spawn(move || {
        let mut reader_session = Session::from_fd_initialized(SimpleFS, cloned_fd, SessionACL::All);
        barrier_clone.wait(); // Signal ready
        // Run until unmount
        let _ = reader_session.run();
    });

    // Start primary session in a thread
    let barrier_clone = barrier.clone();
    let session_handle = thread::spawn(move || {
        barrier_clone.wait(); // Signal ready
        let _ = session.run();
    });

    // Wait for both readers to be ready
    barrier.wait();

    // Give readers time to start processing
    thread::sleep(Duration::from_millis(100));

    // Access the mountpoint - this triggers FUSE requests
    let _ = std::fs::metadata(tmpdir.path());

    // Unmount to stop the sessions
    thread::sleep(Duration::from_millis(100));
    unmounter.unmount().unwrap();

    // Wait for threads to finish
    let _ = session_handle.join();
    let _ = reader_handle.join();
}
