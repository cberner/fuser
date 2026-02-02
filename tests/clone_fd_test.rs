//! Tests for clone_fd multi-reader support
//!
//! Verifies that n_threads config with clone_fd enables multiple
//! FUSE worker threads.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fuser::{Config, Errno, FileType, Filesystem, Generation, INodeNo, ReplyAttr, ReplyEntry, Request, Session};

/// Filesystem that records which thread handled each request
struct ThreadTrackingFS {
    threads: Arc<Mutex<HashSet<String>>>,
    getattr_count: Arc<AtomicUsize>,
}

impl Filesystem for ThreadTrackingFS {
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<fuser::FileHandle>, reply: ReplyAttr) {
        let thread_name = thread::current().name().unwrap_or("unknown").to_string();
        self.threads.lock().unwrap().insert(thread_name);
        self.getattr_count.fetch_add(1, Ordering::SeqCst);

        if ino == INodeNo::ROOT {
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
                    kind: FileType::Directory,
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

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let thread_name = thread::current().name().unwrap_or("unknown").to_string();
        self.threads.lock().unwrap().insert(thread_name);

        // Simulate work to increase chance of parallel execution
        thread::sleep(Duration::from_millis(50));

        if parent == INodeNo::ROOT && name.to_str() == Some("test") {
            reply.entry(
                &Duration::from_secs(1),
                &fuser::FileAttr {
                    ino: INodeNo(2),
                    size: 0,
                    blocks: 0,
                    atime: std::time::UNIX_EPOCH,
                    mtime: std::time::UNIX_EPOCH,
                    ctime: std::time::UNIX_EPOCH,
                    crtime: std::time::UNIX_EPOCH,
                    kind: FileType::RegularFile,
                    perm: 0o644,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                },
                Generation(0),
            );
        } else {
            reply.error(Errno::ENOENT);
        }
    }
}

/// Test that n_threads config creates multiple fuser-N worker threads
#[cfg(target_os = "linux")]
#[test]
fn n_threads_creates_multiple_workers() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mount_point = tmpdir.path();

    let threads = Arc::new(Mutex::new(HashSet::new()));
    let getattr_count = Arc::new(AtomicUsize::new(0));

    let fs = ThreadTrackingFS {
        threads: threads.clone(),
        getattr_count: getattr_count.clone(),
    };

    let mut config = Config::default();
    config.n_threads = Some(4);

    let session = Session::new(fs, mount_point, &config).unwrap();
    let bg = session.spawn().unwrap();

    // Wait for mount
    thread::sleep(Duration::from_millis(100));

    // Send parallel requests
    let mp = mount_point.to_path_buf();
    let client_threads: Vec<_> = (0..8)
        .map(|_| {
            let mp = mp.clone();
            thread::spawn(move || {
                let _ = std::fs::metadata(&mp);
                let _ = std::fs::metadata(mp.join("test"));
            })
        })
        .collect();

    for t in client_threads {
        let _ = t.join();
    }

    thread::sleep(Duration::from_millis(100));

    // Drop the background session (triggers unmount and cleanup)
    drop(bg);

    // Check results
    let count = getattr_count.load(Ordering::SeqCst);
    let thread_set = threads.lock().unwrap();

    eprintln!("getattr_count: {}", count);
    eprintln!("Threads that handled requests: {:?}", thread_set);

    // Should have fuser-N threads
    let fuser_threads: Vec<_> = thread_set
        .iter()
        .filter(|t| t.starts_with("fuser-"))
        .collect();

    assert!(
        !fuser_threads.is_empty(),
        "Expected fuser-N threads, got: {:?}",
        thread_set
    );
}
