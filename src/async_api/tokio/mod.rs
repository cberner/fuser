use std::{
    io,
    path::Path,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    task::{Context, Poll},
};

use futures::{future::join_all, Future};
use log::warn;
use tokio::{sync::Mutex, task::JoinHandle};

use self::io_ops::SubChannel;
use libc::{EAGAIN, EINTR, ENODEV, ENOENT};

use super::{
    active_session::{SessionConfiguration, Worker},
    opened_session::{OpenedFlavor, OpenedSession},
    ActiveSession, Filesystem, SessionHandle,
};

#[cfg(all(not(feature = "libfuse"), feature = "async_impl"))]
use crate::MountOption;

#[cfg(all(feature = "libfuse", feature = "async_impl"))]
use std::ffi::OsStr;

mod channel;
mod io_ops;

#[derive(Debug)]
pub(crate) struct TokioSession {
    pub session_configuration: Arc<Mutex<SessionConfiguration>>,
    /// True if the filesystem is initialized (init operation done)
    is_initialized: AtomicBool,
    /// True if the filesystem was destroyed (destroy operation done)
    is_destroyed: AtomicBool,
    /// Pipes to inform all of the child channels/interested parties we are shutting down
    pub destroy_signals: Arc<Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,

    join_handles: Arc<Mutex<Vec<JoinHandle<Result<(), io::Error>>>>>,
    driver_join: Arc<Mutex<Option<JoinHandle<Result<(), io::Error>>>>>,
    driver_receiver: Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
    channel: Arc<Mutex<Option<channel::Channel>>>,
}

impl TokioSession {
    async fn register_destroy(&self, sender: tokio::sync::oneshot::Sender<()>) {
        let mut guard = self.destroy_signals.lock().await;
        guard.push(sender)
    }
    fn new(channel: channel::Channel) -> Self {
        Self {
            session_configuration: Arc::new(Mutex::new(Default::default())),
            is_initialized: AtomicBool::new(false),
            is_destroyed: AtomicBool::new(false),
            destroy_signals: Arc::new(Mutex::new(Vec::default())),
            join_handles: Arc::new(Mutex::new(Vec::default())),
            driver_join: Arc::new(Mutex::new(None)),
            driver_receiver: Arc::new(Mutex::new(None)),
            channel: Arc::new(Mutex::new(Some(channel))),
        }
    }
}

#[async_trait::async_trait]
impl SessionHandle for TokioSession {
    async fn destroy(&self) -> () {
        self.is_destroyed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut guard = self.destroy_signals.lock().await;

        for e in guard.drain(..) {
            if let Err(e) = e.send(()) {
                warn!("Unable to send a shutdown signal: {:?}", e);
            }
        }

        let mut chan = self.channel.lock().await;
        chan.take();
    }

    async fn wait_destroy(&self) -> () {
        let mut d = self.driver_receiver.lock().await;
        if let Some(e) = d.take() {
            let _ = e.await;
        }
        ()
    }
}

#[async_trait::async_trait]
impl ActiveSession for TokioSession {
    fn destroyed(&self) -> bool {
        self.is_destroyed.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn initialized(&self) -> bool {
        self.is_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn initialize(&self, version: &crate::ll::Version) -> () {
        let mut cfg = self.session_configuration.lock().await;
        cfg.proto_major = version.major();
        cfg.proto_minor = version.minor();
        self.is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn wait_worker_shutdown(&self) -> () {
        let mut join_handles = self.join_handles.lock().await;
        for ret in join_all(join_handles.drain(..)).await {
            if let Err(e) = ret {
                warn!("Error joining worker of {:?}", e);
            }
        }
    }

    async fn session_configuration(&self) -> Option<super::active_session::SessionConfiguration> {
        let cfg = self.session_configuration.lock().await;
        if cfg.proto_major > 0 {
            Some((*cfg).clone())
        } else {
            None
        }
    }
}

struct WorkerIsTerminated(Option<Pin<Box<tokio::sync::oneshot::Receiver<()>>>>);
impl<'a> Future for &'a mut WorkerIsTerminated {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let e = self.0.take();
        if let Some(mut e) = e {
            if let Poll::Pending = e.as_mut().poll(cx) {
                self.0 = Some(e);
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        } else {
            Poll::Ready(())
        }
    }
}

struct TokioWorker {
    terminated: WorkerIsTerminated,
    sub_channel: Arc<SubChannel>,
}

#[async_trait::async_trait]
impl Worker for TokioWorker {
    async fn wait_for_shutdown(&mut self) -> () {
        let r = &mut self.terminated;
        let _ = r.await;
        ()
    }

    async fn read_single_request<'a, 'b>(
        &mut self,
        buffer: &'b mut [u8],
    ) -> Option<io::Result<super::Request<'b>>> {
        let sub_channel = self.sub_channel.clone();

        let r = tokio::select! {
         _ = self.wait_for_shutdown() => {
             Ok(None)
         }
        result = sub_channel.do_receive(buffer) => {
             result
         }
        };
        match r {
            Err(err) => match err.raw_os_error() {
                // Operation interrupted. Accordingly to FUSE, this is safe to retry
                Some(ENOENT) => None,
                // Interrupted system call, retry
                Some(EINTR) => None,
                // Explicitly try again
                Some(EAGAIN) => None,
                // Filesystem was unmounted, quit the loop
                Some(ENODEV) => Some(Err(err)),
                // Unhandled error
                _ => Some(Err(err)),
            },
            Ok(Some(size)) => {
                if let Some(req) = crate::async_api::Request::new(&buffer[..size]) {
                    Some(Ok(req))
                } else {
                    None
                }
            }
            Ok(None) => None,
        }
    }

    async fn sender(&self) -> Arc<dyn super::reply::ReplySender> {
        self.sub_channel.clone()
    }
}

pub(in crate::async_api) struct OpenedTokio {
    channel: channel::Channel,
}

#[async_trait::async_trait]
impl OpenedFlavor for OpenedTokio {
    async fn spawn_run(
        self,
        filesystem: Arc<dyn Filesystem>,
    ) -> io::Result<Arc<dyn SessionHandle>> {
        let OpenedTokio { channel } = self;

        let sub_channels = channel.sub_channels.clone();
        let active_session = Arc::new(TokioSession::new(channel));
        let (sender, driver_receiver) = tokio::sync::oneshot::channel();
        let mut s = active_session.driver_receiver.lock().await;
        *s = Some(driver_receiver);
        drop(s);

        active_session.register_destroy(sender).await;
        let mut join_handles = active_session.join_handles.lock().await;
        for sub_channel in sub_channels.iter() {
            let active_session = Arc::clone(&active_session);
            let filesystem = Arc::clone(&filesystem);
            let finalizer_active_session = active_session.clone();
            let (sender, receiver) = tokio::sync::oneshot::channel();

            let sub_channel = sub_channel.clone();
            active_session.register_destroy(sender).await;
            join_handles.push(tokio::spawn(async move {
                let mut worker = TokioWorker {
                    terminated: WorkerIsTerminated(Some(Box::pin(receiver))),
                    sub_channel: sub_channel,
                };
                let r = super::active_session::spawn_worker_loop(
                    active_session,
                    &mut worker,
                    filesystem,
                )
                .await;
                // once any worker finishes/exits, then then the entire session shout be shut down.
                finalizer_active_session.destroy().await;
                r
            }));
        }

        drop(join_handles);

        let session_2 = Arc::clone(&active_session);
        let mut opt_l = active_session.driver_join.lock().await;
        *opt_l = Some(tokio::task::spawn(super::active_session::driver_evt_loop(
            session_2, filesystem,
        )));

        drop(opt_l);
        Ok(active_session)
    }
}

impl OpenedTokio {
    #[cfg(all(feature = "libfuse", feature = "async_impl"))]
    pub fn create<FS: Filesystem + 'static>(
        filesystem: FS,
        worker_channel_count: usize,
        mountpoint: &Path,
        options: &[&OsStr],
    ) -> io::Result<OpenedSession<FS, OpenedTokio>> {
        let ch = channel::Channel::new(mountpoint, worker_channel_count, options)?;

        let opened_flavor = OpenedTokio { channel: ch };

        Ok(OpenedSession {
            filesystem,
            opened_flavor,
        })
    }

    /// Create a new session by mounting the given filesystem to the given mountpoint
    #[cfg(all(not(feature = "libfuse"), feature = "async_impl"))]
    pub fn create2<FS: Filesystem + 'static>(
        filesystem: FS,
        worker_channel_count: usize,
        mountpoint: &Path,
        options: &[MountOption],
    ) -> io::Result<OpenedSession<FS, OpenedTokio>> {
        channel::Channel::new2(mountpoint, worker_channel_count, options).map(|ch| {
            let opened_flavor = OpenedTokio { channel: ch };
            OpenedSession {
                filesystem,
                opened_flavor,
            }
        })
    }
}
