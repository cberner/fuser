//! Test that clone_fd enables true parallel request handling.
//!
//! Uses a barrier to prove N threads are executing concurrently.
//! Without clone_fd, threads serialize on read() and barrier times out.

use std::ffi::OsStr;
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;

use fuser::Config;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileType;
use fuser::Filesystem;
use fuser::Generation;
use fuser::INodeNo;
use fuser::InitFlags;
use fuser::KernelConfig;
use fuser::ReplyAttr;
use fuser::ReplyEntry;
use fuser::Request;
use fuser::Session;
use tempfile::TempDir;

const N_THREADS: usize = 4;

struct BarrierFS {
    barrier: Arc<Barrier>,
    barrier_reached: Arc<AtomicBool>,
}

impl Filesystem for BarrierFS {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // Request FUSE_PARALLEL_DIROPS so the kernel allows parallel lookups.
        // Without this, the kernel serializes directory operations, defeating clone_fd.
        if let Err(unsupported) = config.add_capabilities(InitFlags::FUSE_PARALLEL_DIROPS) {
            eprintln!(
                "Warning: Kernel does not support FUSE_PARALLEL_DIROPS: {:?}",
                unsupported
            );
        }
        Ok(())
    }

    fn getattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: ReplyAttr,
    ) {
        if ino == INodeNo::ROOT {
            reply.attr(
                &Duration::from_secs(0),
                &FileAttr {
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

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let thread_name = std::thread::current().name().unwrap_or("unknown").to_string();
        eprintln!("Server thread {} got lookup for {:?}", thread_name, name);

        // Accept any file starting with "barrier" (barrier0, barrier1, etc.)
        let name_str = name.to_str().unwrap_or("");
        if parent == INodeNo::ROOT && name_str.starts_with("barrier") {
            eprintln!("Server thread {} waiting at barrier...", thread_name);
            // Wait at the barrier - requires N_THREADS concurrent threads
            self.barrier.wait();
            eprintln!("Server thread {} passed barrier!", thread_name);
            self.barrier_reached.store(true, Ordering::SeqCst);

            reply.entry(
                &Duration::from_secs(0),
                &FileAttr {
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

/// Test that clone_fd enables N threads to handle requests concurrently.
///
/// The barrier requires exactly N_THREADS to arrive before any can proceed.
/// If clone_fd works: N threads read requests in parallel, all reach barrier, pass.
/// If clone_fd broken: only 1 thread in read() at a time, barrier never completes.
#[cfg(target_os = "linux")]
#[test]
fn clone_fd_enables_concurrent_handlers() {
    let tmpdir = TempDir::new().unwrap();
    let mount_point = tmpdir.path();

    let barrier = Arc::new(Barrier::new(N_THREADS));
    let barrier_reached = Arc::new(AtomicBool::new(false));

    let fs = BarrierFS {
        barrier: barrier.clone(),
        barrier_reached: barrier_reached.clone(),
    };

    let mut config = Config::default();
    config.n_threads = Some(N_THREADS);
    config.clone_fd = true;

    eprintln!("Creating session...");
    let session = Session::new(fs, mount_point, &config).unwrap();
    eprintln!("Spawning background session...");
    let bg = session.spawn().unwrap();

    // Wait for mount
    eprintln!("Waiting for mount...");
    thread::sleep(Duration::from_millis(200));
    eprintln!("Mount should be ready");

    // Spawn N_THREADS client threads, each doing a lookup
    // All must reach the barrier simultaneously for any to proceed
    eprintln!("Spawning {} client threads...", N_THREADS);
    let mp = mount_point.to_path_buf();
    let clients: Vec<_> = (0..N_THREADS)
        .map(|i| {
            let mp = mp.clone();
            thread::spawn(move || {
                eprintln!("Client {} looking up barrier{}...", i, i);
                // Each client looks up a different file to avoid dentry contention
                let result = std::fs::metadata(mp.join(format!("barrier{}", i)));
                eprintln!("Client {} done: {:?}", i, result.is_ok());
            })
        })
        .collect();
    eprintln!("All client threads spawned");

    // Wait for clients with timeout
    let start = std::time::Instant::now();
    for client in clients {
        let remaining = Duration::from_secs(10).saturating_sub(start.elapsed());
        if remaining.is_zero() {
            panic!("Timeout: barrier not reached - clone_fd may not be working");
        }
        // Note: std thread::join doesn't have timeout, so we just join
        // The barrier itself will block if clone_fd isn't working
        client.join().expect("Client thread panicked");
    }

    assert!(
        barrier_reached.load(Ordering::SeqCst),
        "Barrier was never reached - clone_fd not enabling parallel execution"
    );

    drop(bg);
}
