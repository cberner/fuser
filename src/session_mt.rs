//! Multi-threaded session implementation
//!
//! This module provides a multi-threaded session loop for FUSE filesystems,
//! based on the design from libfuse's fuse_loop_mt.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::{debug, error, info, warn};
use std::cell::UnsafeCell;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use crate::channel::Channel;
use crate::ll::fuse_abi::fuse_opcode::{FUSE_FORGET, FUSE_BATCH_FORGET};
use crate::mnt::Mount;
use crate::request::Request;
use crate::session::{aligned_sub_buf, Session, SessionACL, BUFFER_SIZE};
use crate::Filesystem;

/// Default maximum number of worker threads
const DEFAULT_MAX_THREADS: usize = 10;

/// Default maximum idle threads (-1 means thread destruction is disabled)
const DEFAULT_MAX_IDLE_THREADS: i32 = -1;

/// Maximum reasonable number of threads to prevent resource exhaustion
const MAX_THREADS_LIMIT: usize = 100_000;

/// Configuration for multi-threaded session loop
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum number of worker threads
    pub max_threads: usize,
    /// Maximum number of idle threads before they are destroyed
    /// Set to -1 to disable thread destruction (recommended for performance)
    pub max_idle_threads: i32,
    /// Whether to clone the /dev/fuse file descriptor for each thread
    /// This may improve performance by allowing parallel kernel operations
    pub clone_fd: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_threads: DEFAULT_MAX_THREADS,
            max_idle_threads: DEFAULT_MAX_IDLE_THREADS,
            clone_fd: false,
        }
    }
}

impl SessionConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of worker threads
    pub fn max_threads(mut self, max_threads: usize) -> Self {
        self.max_threads = max_threads.min(MAX_THREADS_LIMIT);
        self
    }

    /// Set the maximum number of idle threads
    pub fn max_idle_threads(mut self, max_idle_threads: i32) -> Self {
        self.max_idle_threads = max_idle_threads;
        self
    }

    /// Enable or disable fd cloning
    pub fn clone_fd(mut self, clone_fd: bool) -> Self {
        self.clone_fd = clone_fd;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> io::Result<()> {
        if self.max_threads == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_threads must be at least 1",
            ));
        }
        if self.max_threads > MAX_THREADS_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("max_threads cannot exceed {}", MAX_THREADS_LIMIT),
            ));
        }
        Ok(())
    }
}

/// Worker thread state
#[allow(dead_code)]
struct Worker {
    thread: Option<JoinHandle<()>>,
    id: usize,
}

impl Worker {
    fn new(id: usize, thread: JoinHandle<()>) -> Self {
        Self {
            thread: Some(thread),
            id,
        }
    }
}

/// Shared state for the multi-threaded session
struct MtState {
    /// Number of worker threads
    num_workers: usize,
    /// Number of available (idle) worker threads
    num_available: usize,
    /// Worker threads
    workers: Vec<Worker>,
    /// Whether the session should exit
    exit: bool,
    /// Error from worker threads
    error: Option<io::Error>,
}

impl MtState {
    fn new() -> Self {
        Self {
            num_workers: 0,
            num_available: 0,
            workers: Vec::new(),
            exit: false,
            error: None,
        }
    }
}

/// Wrapper around UnsafeCell that implements Sync when T is Sync
///
/// SAFETY: This type allows concurrent access to the inner value.
/// It is only safe to use when T implements Sync, meaning T can be
/// safely accessed from multiple threads simultaneously.
struct SyncUnsafeCell<T>(UnsafeCell<T>);

impl<T> SyncUnsafeCell<T> {
    fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// SAFETY: SyncUnsafeCell<T> is Sync when T is Sync
// This allows Arc<SyncUnsafeCell<T>> to be Send across threads
unsafe impl<T: Sync> Sync for SyncUnsafeCell<T> {}

/// Multi-threaded session runner
///
/// SAFETY: This structure uses `SyncUnsafeCell` to allow concurrent access to the filesystem.
/// The filesystem MUST be thread-safe (Sync). The caller is responsible for ensuring
/// that the filesystem implementation can handle concurrent calls safely.
pub struct MtSession<FS: Filesystem> {
    state: Arc<(Mutex<MtState>, Condvar)>,
    config: SessionConfig,
    /// SAFETY: SyncUnsafeCell allows interior mutability. Multiple threads will access this
    /// concurrently. The FS type must implement Sync to ensure thread-safety.
    filesystem: Arc<SyncUnsafeCell<FS>>,
    channel: Channel,
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
    session_owner: u32,
    proto_major: Arc<Mutex<u32>>,
    proto_minor: Arc<Mutex<u32>>,
    allowed: SessionACL,
    initialized: Arc<AtomicBool>,
    destroyed: Arc<AtomicBool>,
    worker_counter: Arc<AtomicUsize>,
}

// SAFETY: MtSession is Send + Sync when FS is Send + Sync
unsafe impl<FS: Filesystem + Send + Sync> Send for MtSession<FS> {}
unsafe impl<FS: Filesystem + Send + Sync> Sync for MtSession<FS> {}

impl<FS: Filesystem> std::fmt::Debug for MtSession<FS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtSession")
            .field("config", &self.config)
            .field("mount", &self.mount)
            .field("session_owner", &self.session_owner)
            .field("proto_major", &self.proto_major)
            .field("proto_minor", &self.proto_minor)
            .field("allowed", &self.allowed)
            .field("initialized", &self.initialized)
            .field("destroyed", &self.destroyed)
            .finish()
    }
}

impl<FS: Filesystem> MtSession<FS> {
    /// Request all workers to exit
    pub fn exit(&self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.exit = true;
        cvar.notify_all();
    }
}

impl<FS: Filesystem + Send + Sync + 'static> MtSession<FS> {
    /// Create a new multi-threaded session from a regular session
    ///
    /// # Safety Requirements
    ///
    /// The filesystem type FS must be thread-safe (implement Sync). This means:
    /// - For read-only filesystems: No problem, they are naturally thread-safe
    /// - For filesystems with mutable state: Must use interior mutability (Mutex, RwLock, etc.)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // For a read-only filesystem like HelloFS, just derive Sync
    /// struct HelloFS;  // Already Sync by default if no interior mutability
    ///
    /// // For a filesystem with state, use interior mutability:
    /// struct MyFS {
    ///     state: Arc<Mutex<State>>,  // Use Mutex/RwLock for mutable state
    /// }
    /// ```
    pub fn from_session(session: Session<FS>, config: SessionConfig) -> io::Result<Self> {
        config.validate()?;

        // Use ManuallyDrop to prevent Session's Drop from running
        let manual_session = std::mem::ManuallyDrop::new(session);

        // Clone the channel (this is safe since Channel is Clone)
        let channel = manual_session.ch.clone();

        // Clone the mount Arc to keep the mount alive
        let mount = manual_session.mount.clone();

        // Extract values we need
        let session_owner = manual_session.session_owner;
        let proto_major = manual_session.proto_major;
        let proto_minor = manual_session.proto_minor;
        let allowed = manual_session.allowed;
        let initialized = manual_session.initialized;

        // Safely extract the filesystem using ptr::read
        let filesystem = unsafe {
            std::ptr::read(&manual_session.filesystem as *const FS)
        };

        Ok(Self {
            state: Arc::new((Mutex::new(MtState::new()), Condvar::new())),
            config,
            filesystem: Arc::new(SyncUnsafeCell::new(filesystem)),
            channel,
            mount,
            session_owner,
            proto_major: Arc::new(Mutex::new(proto_major)),
            proto_minor: Arc::new(Mutex::new(proto_minor)),
            allowed,
            initialized: Arc::new(AtomicBool::new(initialized)),
            destroyed: Arc::new(AtomicBool::new(false)),
            worker_counter: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Run the multi-threaded session loop
    pub fn run(&mut self) -> io::Result<()> {
        info!("Starting multi-threaded FUSE session with max {} threads", self.config.max_threads);

        // Pre-create all worker threads so they can all wait on receive()
        // This is essential for true parallelism - multiple threads must be
        // waiting in receive() to handle concurrent requests from the kernel
        for _ in 0..self.config.max_threads {
            self.start_worker()?;
        }

        // Wait for workers to finish
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        while state.num_workers > 0 && !state.exit {
            state = cvar.wait(state).unwrap();
        }

        // Collect any error
        let result = if let Some(err) = state.error.take() {
            Err(err)
        } else {
            Ok(())
        };

        info!("Multi-threaded FUSE session ended");
        result
    }

    /// Start a new worker thread
    fn start_worker(&self) -> io::Result<()> {
        let worker_id = self.worker_counter.fetch_add(1, Ordering::SeqCst);

        let state = self.state.clone();
        let config = self.config.clone();
        let filesystem = self.filesystem.clone();

        // Clone the channel if clone_fd is enabled, otherwise share the same channel
        let channel = if self.config.clone_fd {
            match self.channel.clone_fd() {
                Ok(ch) => ch,
                Err(e) => {
                    warn!("Failed to clone fd for worker {}, using shared channel: {}", worker_id, e);
                    self.channel.clone()
                }
            }
        } else {
            self.channel.clone()
        };

        let proto_major = self.proto_major.clone();
        let proto_minor = self.proto_minor.clone();
        let allowed = self.allowed.clone();
        let initialized = self.initialized.clone();
        let destroyed = self.destroyed.clone();
        let session_owner = self.session_owner;
        let worker_counter = self.worker_counter.clone();
        let master_channel = self.channel.clone();

        let thread = thread::Builder::new()
            .name(format!("fuse-worker-{}", worker_id))
            .spawn(move || {
                worker_main(
                    worker_id,
                    state,
                    config,
                    filesystem,
                    channel,
                    session_owner,
                    proto_major,
                    proto_minor,
                    allowed,
                    initialized,
                    destroyed,
                    worker_counter,
                    master_channel,
                )
            })?;

        let (lock, _cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.workers.push(Worker::new(worker_id, thread));
        state.num_workers += 1;
        state.num_available += 1;

        debug!("Started worker thread {} (total: {})", worker_id, state.num_workers);
        Ok(())
    }
}

/// Main function for worker threads
#[allow(unused_variables)]
fn worker_main<FS: Filesystem + Send + Sync + 'static>(
    worker_id: usize,
    state: Arc<(Mutex<MtState>, Condvar)>,
    config: SessionConfig,
    filesystem: Arc<SyncUnsafeCell<FS>>,
    channel: Channel,
    session_owner: u32,
    proto_major: Arc<Mutex<u32>>,
    proto_minor: Arc<Mutex<u32>>,
    allowed: SessionACL,
    initialized: Arc<AtomicBool>,
    destroyed: Arc<AtomicBool>,
    worker_counter: Arc<AtomicUsize>,
    master_channel: Channel,
) {
    debug!("Worker {} started", worker_id);

    // Each worker has its own buffer to avoid contention
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let (lock, cvar) = &*state;

    loop {
        // Check if we should exit
        {
            let state = lock.lock().unwrap();
            if state.exit {
                debug!("Worker {} exiting due to session exit", worker_id);
                break;
            }
        }

        // Mark as available before blocking on receive
        {
            let mut state = lock.lock().unwrap();
            state.num_available += 1;
        }

        // Align buffer for fuse headers
        let buf = aligned_sub_buf(&mut buffer, std::mem::align_of::<crate::ll::fuse_abi::fuse_in_header>());

        // Receive request from kernel (this blocks)
        let size = match channel.receive(buf) {
            Ok(size) => size,
            Err(err) => {
                // Handle errors
                match err.raw_os_error() {
                    Some(
                          ENOENT // Operation interrupted, safe to retry
                        | EINTR // Interrupted system call, retry
                        | EAGAIN // Explicitly instructed to try again
                    ) => {
                        // Decrease available count and continue
                        let mut state = lock.lock().unwrap();
                        state.num_available -= 1;
                        continue;
                    }
                    Some(ENODEV) => {
                        // Device not available, exit
                        debug!("Worker {} received ENODEV, exiting", worker_id);
                        let mut state = lock.lock().unwrap();
                        state.exit = true;
                        state.num_available -= 1;
                        cvar.notify_all();
                        break;
                    }
                    _ => {
                        // Unhandled error
                        error!("Worker {} error receiving request: {}", worker_id, err);
                        let mut state = lock.lock().unwrap();
                        state.error = Some(err);
                        state.exit = true;
                        state.num_available -= 1;
                        cvar.notify_all();
                        break;
                    }
                }
            }
        };

        // Mark as busy after receiving
        let should_spawn_thread = {
            let mut state = lock.lock().unwrap();
            state.num_available -= 1;

            // Check if we should spawn a new thread
            // Don't spawn for FORGET operations to avoid thread explosion
            let is_forget = if size >= std::mem::size_of::<crate::ll::fuse_abi::fuse_in_header>() {
                let header = unsafe {
                    &*(buf.as_ptr() as *const crate::ll::fuse_abi::fuse_in_header)
                };
                header.opcode == FUSE_FORGET as u32
                    || header.opcode == FUSE_BATCH_FORGET as u32
            } else {
                false
            };

            !is_forget
                && state.num_available == 0
                && state.num_workers < config.max_threads
                && initialized.load(Ordering::SeqCst)
        };

        // Spawn new worker if needed (outside the lock)
        if should_spawn_thread {
            let new_worker_id = worker_counter.fetch_add(1, Ordering::SeqCst);
            let state_clone = state.clone();
            let config_clone = config.clone();
            let filesystem_clone = filesystem.clone();
            let proto_major_clone = proto_major.clone();
            let proto_minor_clone = proto_minor.clone();
            let allowed_clone = allowed.clone();
            let initialized_clone = initialized.clone();
            let destroyed_clone = destroyed.clone();
            let worker_counter_clone = worker_counter.clone();
            let master_channel_clone = master_channel.clone();

            // Clone the channel if clone_fd is enabled
            let new_channel = if config.clone_fd {
                match master_channel.clone_fd() {
                    Ok(ch) => ch,
                    Err(e) => {
                        warn!("Failed to clone fd for worker {}, using shared channel: {}", new_worker_id, e);
                        master_channel.clone()
                    }
                }
            } else {
                master_channel.clone()
            };

            // Spawn the new worker thread
            match thread::Builder::new()
                .name(format!("fuse-worker-{}", new_worker_id))
                .spawn(move || {
                    worker_main(
                        new_worker_id,
                        state_clone,
                        config_clone,
                        filesystem_clone,
                        new_channel,
                        session_owner,
                        proto_major_clone,
                        proto_minor_clone,
                        allowed_clone,
                        initialized_clone,
                        destroyed_clone,
                        worker_counter_clone,
                        master_channel_clone,
                    )
                })
            {
                Ok(thread) => {
                    let (lock, _) = &*state;
                    let mut mt_state = lock.lock().unwrap();
                    mt_state.workers.push(Worker::new(new_worker_id, thread));
                    mt_state.num_workers += 1;
                    mt_state.num_available += 1;
                    debug!("Spawned new worker thread {} (total: {})", new_worker_id, mt_state.num_workers);
                }
                Err(e) => {
                    error!("Failed to spawn worker thread {}: {}", new_worker_id, e);
                }
            }
        }

        // Process the request
        if let Some(req) = Request::new(channel.sender(), &buf[..size]) {
            // We need to dispatch the request
            // Since we can't create a full Session in a multi-threaded context,
            // we'll create a temporary minimal Session just for dispatch
            //
            // SAFETY: We use SyncUnsafeCell to allow concurrent access to the filesystem.
            // This is safe because:
            // 1. The filesystem type FS is required to implement Sync (see MtSession trait bounds)
            // 2. For read-only filesystems, concurrent access is naturally safe
            // 3. For filesystems with mutable state, they must use interior mutability
            //    (Mutex, RwLock, etc.) to synchronize access
            //
            // We temporarily move the filesystem out of SyncUnsafeCell to create a Session,
            // dispatch the request, then move it back. Multiple threads may do this
            // concurrently, which is why FS must be Sync.
            let fs_ptr = filesystem.get();

            // Read the filesystem value out (temporarily moving it)
            let fs_value = unsafe { std::ptr::read(fs_ptr) };

            // Create a minimal temporary session for dispatching
            let temp_mount = Arc::new(Mutex::new(None));
            let mut temp_session = Session {
                filesystem: fs_value,
                ch: channel.clone(),
                mount: temp_mount,
                allowed,
                session_owner,
                proto_major: *proto_major.lock().unwrap(),
                proto_minor: *proto_minor.lock().unwrap(),
                initialized: initialized.load(Ordering::SeqCst),
                destroyed: destroyed.load(Ordering::SeqCst),
            };

            // Dispatch the request
            req.dispatch(&mut temp_session);

            // Move filesystem back using ptr::read
            let fs_back = unsafe { std::ptr::read(&temp_session.filesystem as *const FS) };
            unsafe { std::ptr::write(fs_ptr, fs_back); }

            // Update proto versions if they changed during init
            if temp_session.proto_major != *proto_major.lock().unwrap() {
                *proto_major.lock().unwrap() = temp_session.proto_major;
            }
            if temp_session.proto_minor != *proto_minor.lock().unwrap() {
                *proto_minor.lock().unwrap() = temp_session.proto_minor;
            }

            // Update initialized flag
            if temp_session.initialized != initialized.load(Ordering::SeqCst) {
                initialized.store(temp_session.initialized, Ordering::SeqCst);
            }

            // Prevent temp_session from being dropped (we already moved filesystem out)
            std::mem::forget(temp_session);
        }

        // Check for idle thread cleanup
        // Note: availability is restored at the start of the next loop iteration
        {
            let mut state = lock.lock().unwrap();
            // Temporarily increment to check idle condition
            let current_available = state.num_available + 1; // +1 for this thread about to become available

            if config.max_idle_threads != -1
                && current_available > config.max_idle_threads as usize
                && state.num_workers > 1
            {
                debug!("Worker {} exiting (idle cleanup)", worker_id);
                state.num_workers -= 1;
                break;
            }
        }
    }

    // Notify that this worker is done
    cvar.notify_all();
    debug!("Worker {} finished", worker_id);
}

impl<FS: Filesystem> Drop for MtSession<FS> {
    fn drop(&mut self) {
        self.exit();

        // Wait for all workers to finish
        let (lock, _cvar) = &*self.state;

        // Collect workers to join
        let workers = {
            let mut state = lock.lock().unwrap();
            std::mem::take(&mut state.workers)
        };

        // Join all workers outside the lock
        for worker in workers {
            if let Some(thread) = worker.thread {
                let _ = thread.join();
            }
        }
    }
}
