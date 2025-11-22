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

    /// Check if running in single-threaded mode
    pub fn is_single_threaded(&self) -> bool {
        self.max_threads == 1
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
    /// Number of worker threads (atomic for lock-free access)
    num_workers: AtomicUsize,
    /// Number of available (idle) worker threads (atomic for lock-free access)
    num_available: AtomicUsize,
    /// Whether the session should exit (atomic for lock-free access)
    exit: AtomicBool,
    /// Protected state for thread management
    inner: Mutex<MtStateInner>,
    /// Condition variable for signaling exit completion
    cvar: Condvar,
}

struct MtStateInner {
    /// Worker threads
    workers: Vec<Worker>,
    /// Error from worker threads
    error: Option<io::Error>,
}

impl MtState {
    fn new() -> Self {
        Self {
            num_workers: AtomicUsize::new(0),
            num_available: AtomicUsize::new(0),
            exit: AtomicBool::new(false),
            inner: Mutex::new(MtStateInner {
                workers: Vec::new(),
                error: None,
            }),
            cvar: Condvar::new(),
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
    state: Arc<MtState>,
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
        self.state.exit.store(true, Ordering::Release);
        let _unused = self.state.inner.lock();
        self.state.cvar.notify_all();
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
            state: Arc::new(MtState::new()),
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
        let mode = if self.config.is_single_threaded() {
            "single-threaded"
        } else {
            "multi-threaded"
        };
        info!(
            "Starting {} FUSE session (max {} threads)",
            mode, self.config.max_threads
        );

        // Start with exactly ONE worker thread, like libfuse does
        // Additional threads will be created on-demand when all workers are busy
        self.start_worker()?;

        // Wait for workers to finish
        let mut inner = self.state.inner.lock().unwrap();
        while self.state.num_workers.load(Ordering::Acquire) > 0 {
            if self.state.exit.load(Ordering::Acquire) && inner.workers.is_empty() {
                break;
            }
            inner = self.state.cvar.wait(inner).unwrap();
        }

        // Collect any error
        let result = if let Some(err) = inner.error.take() {
            Err(err)
        } else {
            Ok(())
        };

        info!("{} FUSE session ended", mode);
        result
    }

    /// Start a new worker thread
    fn start_worker(&self) -> io::Result<()> {
        let worker_id = self.worker_counter.fetch_add(1, Ordering::SeqCst);

        // Increment total count BEFORE spawning to reserve the slot
        self.state.num_workers.fetch_add(1, Ordering::SeqCst);

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

        let res = thread::Builder::new()
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
            });

        match res {
            Ok(thread) => {
                let mut inner = self.state.inner.lock().unwrap();
                inner.workers.push(Worker::new(worker_id, thread));
                debug!("Worker {} started", worker_id);
                Ok(())
            }
            Err(e) => {
                // Rollback count on failure
                self.state.num_workers.fetch_sub(1, Ordering::SeqCst);
                Err(e)
            }
        }
    }
}

/// Main function for worker threads
#[allow(unused_variables)]
fn worker_main<FS: Filesystem + Send + Sync + 'static>(
    worker_id: usize,
    state: Arc<MtState>,
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
    // Each worker has its own buffer to avoid contention
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut self_cleaned = false;  // Track if we already cleaned up

    // Helper closure to spawn a new thread
    let try_spawn_new_worker = |current_total: usize| {
        // Double check against max threads
        if current_total >= config.max_threads {
            return;
        }

        // Generate new ID
        let new_id = worker_counter.fetch_add(1, Ordering::Relaxed);

        // Reserve slot
        state.num_workers.fetch_add(1, Ordering::SeqCst);

        debug!("Worker {} spawning helper {}", worker_id, new_id);

        // Prepare clones
        let state_c = state.clone();
        let config_c = config.clone();
        let fs_c = filesystem.clone();
        let pm_c = proto_major.clone();
        let pmi_c = proto_minor.clone();
        let al_c = allowed.clone();
        let init_c = initialized.clone();
        let dest_c = destroyed.clone();
        let wc_c = worker_counter.clone();
        let mc_c = master_channel.clone();

        // Clone channel logic
        let ch_c = if config.clone_fd {
            match master_channel.clone_fd() {
                Ok(ch) => ch,
                Err(_) => master_channel.clone(),
            }
        } else {
            master_channel.clone()
        };

        let builder = thread::Builder::new().name(format!("fuse-worker-{}", new_id));
        match builder.spawn(move || {
            worker_main(new_id, state_c, config_c, fs_c, ch_c, session_owner, pm_c, pmi_c, al_c, init_c, dest_c, wc_c, mc_c)
        }) {
            Ok(t) => {
                let mut inner = state.inner.lock().unwrap();
                inner.workers.push(Worker::new(new_id, t));
            },
            Err(e) => {
                error!("Failed to spawn helper: {}", e);
                state.num_workers.fetch_sub(1, Ordering::SeqCst);
            }
        }
    };

    loop {
        // Fast exit check
        if state.exit.load(Ordering::Relaxed) {
            debug!("Worker {} exiting (session exit)", worker_id);
            break;
        }

        // Announce availability
        // We are about to block on receive, so we are "idle"
        state.num_available.fetch_add(1, Ordering::Release);

        let buf = aligned_sub_buf(&mut buffer, std::mem::align_of::<crate::ll::fuse_abi::fuse_in_header>());

        // Block waiting for request
        let res = channel.receive(buf);

        // We woke up, we are busy now
        // Acquire ensures we see updates from other threads
        let prev_idle = state.num_available.fetch_sub(1, Ordering::Acquire);

        let size = match res {
            Ok(s) => s,
            Err(e) => {
                match e.raw_os_error() {
                    Some(ENOENT | EINTR | EAGAIN) => continue,
                    Some(ENODEV) => {
                        debug!("Worker {} exiting (ENODEV)", worker_id);
                        state.exit.store(true, Ordering::Release);
                        let _unused = state.inner.lock();
                        state.cvar.notify_all();
                        break;
                    },
                    _ => {
                        error!("Worker {} error receiving request: {}", worker_id, e);
                        let mut inner = state.inner.lock().unwrap();
                        inner.error = Some(e);
                        state.exit.store(true, Ordering::Release);
                        state.cvar.notify_all();
                        break;
                    }
                }
            }
        };

        // Decision: Do we need more threads?
        // If prev_idle was 1, it is now 0 (we were the last one).
        // If prev_idle was <= 1, it means the pool is exhausted.
        if prev_idle <= 1 {
            // Check opcode for FORGET (optimization)
            let is_forget = if size >= std::mem::size_of::<crate::ll::fuse_abi::fuse_in_header>() {
                let header = unsafe { &*(buf.as_ptr() as *const crate::ll::fuse_abi::fuse_in_header) };
                header.opcode == FUSE_FORGET as u32 || header.opcode == FUSE_BATCH_FORGET as u32
            } else {
                false
            };

            if !is_forget && initialized.load(Ordering::Relaxed) {
                let current_workers = state.num_workers.load(Ordering::Relaxed);
                if current_workers < config.max_threads {
                    // Spawn logic - involves locking
                    try_spawn_new_worker(current_workers);
                }
            }
        }

        // Process the Request
        if let Some(req) = Request::new(channel.sender(), &buf[..size]) {
            // SAFE: FS implements Sync, so multiple &mut FS from different threads are safe
            // because FS uses interior mutability (Mutex/RwLock) to protect its state.
            let fs_ref = unsafe { &mut *filesystem.get() };

            // Get the current state (we need a lock for proto versions)
            let mut proto_major_value = *proto_major.lock().unwrap();
            let mut proto_minor_value = *proto_minor.lock().unwrap();
            let mut initialized_value = initialized.load(Ordering::Relaxed);
            let destroyed_value = destroyed.load(Ordering::Relaxed);

            // Dispatch the request with explicit context
            req.dispatch_with_context(
                fs_ref,
                &allowed,
                session_owner,
                &mut proto_major_value,
                &mut proto_minor_value,
                &mut initialized_value,
                destroyed_value,
            );

            // Update the shared state if it was modified during dispatch
            {
                let mut proto_major_lock = proto_major.lock().unwrap();
                if proto_major_value != *proto_major_lock {
                    *proto_major_lock = proto_major_value;
                }
            }
            {
                let mut proto_minor_lock = proto_minor.lock().unwrap();
                if proto_minor_value != *proto_minor_lock {
                    *proto_minor_lock = proto_minor_value;
                }
            }
            if initialized_value != initialized.load(Ordering::Relaxed) {
                initialized.store(initialized_value, Ordering::SeqCst);
            }
        }

        // Idle thread cleanup logic (Optional / Debounced)
        if config.max_idle_threads != -1 {
            let current_idle = state.num_available.load(Ordering::Relaxed);
            if current_idle > config.max_idle_threads as usize {
                // We have too many idle threads
                let mut inner = state.inner.lock().unwrap();

                // Re-check inside lock to avoid race
                let recheck_idle = state.num_available.load(Ordering::Relaxed);
                let recheck_workers = state.num_workers.load(Ordering::Relaxed);

                if recheck_idle > config.max_idle_threads as usize && recheck_workers > 1 {
                     // Remove ourselves from the list
                     if let Some(pos) = inner.workers.iter().position(|w| w.id == worker_id) {
                         inner.workers.remove(pos);
                     }
                     state.num_workers.fetch_sub(1, Ordering::SeqCst);
                     state.num_available.fetch_sub(1, Ordering::SeqCst);
                     self_cleaned = true;  // Mark that we've cleaned up
                     debug!("Worker {} exiting (idle threads: {} > max: {})",
                            worker_id, recheck_idle, config.max_idle_threads);
                     break;
                }
            }
        }
    }

    // Worker is exiting - clean up (if not already done in idle cleanup)
    if !self_cleaned {
        let mut inner = state.inner.lock().unwrap();
        // Remove ourselves from the workers list
        if let Some(pos) = inner.workers.iter().position(|w| w.id == worker_id) {
            inner.workers.remove(pos);
        }
        // Decrease worker count
        state.num_workers.fetch_sub(1, Ordering::SeqCst);
    }

    // Thread exit notification
    state.cvar.notify_all();
}

impl<FS: Filesystem> Drop for MtSession<FS> {
    fn drop(&mut self) {
        self.exit();

        // Collect workers to join
        let workers = {
            let mut inner = self.state.inner.lock().unwrap();
            std::mem::take(&mut inner.workers)
        };

        // Join all workers outside the lock
        for worker in workers {
            if let Some(thread) = worker.thread {
                let _ = thread.join();
            }
        }
    }
}
