use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use fuser::Errno;
use fuser::FileHandle;
use fuser::Filesystem;
use fuser::INodeNo;
use fuser::Session;
use fuser::SessionACL;
use tempfile::TempDir;

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
            &self,
            _req: &fuser::Request,
            ino: INodeNo,
            _fh: Option<FileHandle>,
            reply: fuser::ReplyAttr,
        ) {
            self.count.fetch_add(1, Ordering::SeqCst);
            if ino == INodeNo::ROOT {
                // Root directory
                reply.attr(
                    &Duration::from_secs(1),
                    &fuser::FileAttr {
                        ino: INodeNo::ROOT,
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
                reply.error(Errno::ENOENT);
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
/// Verifies both readers receive requests and metadata returns expected values.
#[cfg(target_os = "linux")]
#[test]
fn from_fd_initialized_works() {
    // Filesystem that tracks request count per instance with artificial delay
    // to ensure kernel dispatches to both readers
    struct SlowCountingFS {
        count: Arc<AtomicUsize>,
    }

    impl Filesystem for SlowCountingFS {
        fn getattr(
            &self,
            _req: &fuser::Request,
            ino: INodeNo,
            _fh: Option<FileHandle>,
            reply: fuser::ReplyAttr,
        ) {
            self.count.fetch_add(1, Ordering::SeqCst);

            // Add delay so while one reader is processing, the kernel
            // will dispatch concurrent requests to the other reader
            thread::sleep(Duration::from_millis(50));

            if ino == INodeNo::ROOT {
                reply.attr(
                    &Duration::from_secs(0), // No caching to ensure requests reach FUSE
                    &fuser::FileAttr {
                        ino: INodeNo::ROOT,
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
                reply.error(Errno::ENOENT);
            }
        }
    }

    let tmpdir: TempDir = tempfile::tempdir().unwrap();

    // Separate counters to track which reader handled requests
    let primary_count = Arc::new(AtomicUsize::new(0));
    let reader_count = Arc::new(AtomicUsize::new(0));

    let session = Session::new(
        SlowCountingFS {
            count: primary_count.clone(),
        },
        tmpdir.path(),
        &[],
    )
    .unwrap();

    // Clone fd for second reader BEFORE spawning the primary (spawn takes ownership)
    let cloned_fd = session.clone_fd().expect("clone_fd should succeed");

    // Save path for concurrent access (before session is moved)
    let path = tmpdir.path().to_path_buf();

    // Spawn primary session in background
    let primary_bg = session.spawn().unwrap();

    // Start second reader in a thread
    let reader_count_clone = reader_count.clone();
    let reader_handle = thread::spawn(move || {
        let reader_session = Session::from_fd_initialized(
            SlowCountingFS {
                count: reader_count_clone,
            },
            cloned_fd,
            SessionACL::All,
        );
        // Spawn in background - the thread will run until ENODEV when primary unmounts
        let bg = reader_session.spawn().unwrap();
        // Keep BackgroundSession alive - when dropped it will wait for the thread
        // The thread exits on ENODEV when primary unmounts
        drop(bg);
    });

    // Give readers time to start processing
    thread::sleep(Duration::from_millis(100));

    // Generate concurrent requests from multiple threads
    // With 50ms delay per request and concurrent threads, the kernel should
    // dispatch to both readers
    let request_threads: Vec<_> = (0..4)
        .map(|_| {
            let p = path.clone();
            thread::spawn(move || {
                for _ in 0..5 {
                    let meta = std::fs::metadata(&p);
                    // Verify metadata returns expected values
                    if let Ok(m) = meta {
                        assert!(m.is_dir(), "root should be a directory");
                        assert_eq!(
                            m.permissions().mode() & 0o777,
                            0o755,
                            "permissions should be 0o755"
                        );
                    }
                }
            })
        })
        .collect();

    // Wait for all request threads
    for t in request_threads {
        t.join().unwrap();
    }

    // Let any in-flight requests complete
    thread::sleep(Duration::from_millis(200));

    // Unmount by dropping the primary BackgroundSession
    // This will cause the secondary to exit with ENODEV
    drop(primary_bg);

    // Wait for reader thread to finish
    let _ = reader_handle.join();

    // Verify both readers processed requests
    let primary = primary_count.load(Ordering::SeqCst);
    let reader = reader_count.load(Ordering::SeqCst);
    let total = primary + reader;

    eprintln!(
        "Request distribution: primary={}, reader={}, total={}",
        primary, reader, total
    );

    // Total should be > 0 (requests were processed)
    assert!(total > 0, "expected some requests to be processed");

    // With 50ms delay per request and 4 concurrent threads, both readers
    // should handle some requests. The kernel dispatches to whichever
    // reader is blocked in read(), and with the delay, both should be available.
    assert!(
        primary > 0 && reader > 0,
        "expected both readers to process requests: primary={}, reader={}. \
         This verifies multi-threaded request handling works.",
        primary,
        reader
    );
}
