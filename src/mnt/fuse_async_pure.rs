//! Async wrapper for FUSE mounting and unmounting using the pure Rust implementation.
//!
//! We accept that micro-optimizations are possible with this implementation, however, since the a lot of the
//! lower level FUSE interactions are still blocking, effort into this would be premature. As such the main
//! effort is to take the blocking file descriptor and convert it into an AsyncFd so that at runtime we can
//! take advantage of the async runtime for waiting on events and unmounting.

use log::error;
use log::warn;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io;
use tokio::net::UnixStream;

use crate::SessionACL;
use crate::dev_fuse_async::AsyncDevFuse;
use crate::mnt::fuse_pure;
use crate::mnt::is_mounted_async;
use crate::mnt::mount_options::MountOption;

/// Inner implementation of the async mount. This is held by [`super::AsyncMount`] and [`crate::session_async::AsyncSession`] to
/// manage the actual mount (file descriptor) lifecycle.
#[derive(Debug)]
pub(crate) struct AsyncMountImpl {
    mountpoint: CString,
    auto_unmount_socket: Option<UnixStream>,
    unmount_tx: Option<tokio::sync::oneshot::Sender<AsyncMountImpl>>,
    fuse_device: Option<Arc<AsyncDevFuse>>,
}

impl AsyncMountImpl {
    pub(crate) fn new(mountpoint: &Path) -> tokio::io::Result<Self> {
        let mountpoint = mountpoint.canonicalize()?;
        let mountpoint: CString = CString::new(mountpoint.as_os_str().as_bytes())?;

        Ok(AsyncMountImpl {
            mountpoint,
            auto_unmount_socket: None,
            unmount_tx: None,
            fuse_device: None,
        })
    }

    /// Mount the filesystem. This is a no-op if the filesystem is already mounted.
    pub(crate) async fn mount_impl(
        mut self,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<Self> {
        let mountpoint = std::ffi::OsStr::from_bytes(self.mountpoint.as_bytes()).to_os_string();
        let options = options.to_vec();

        let (device, sock) = tokio::task::spawn_blocking(move || {
            fuse_pure::fuse_mount_pure(mountpoint.as_os_str(), &options, acl)
        })
        .await
        .map_err(|_err| io::Error::other("blocking task panicked"))??;

        let async_device = AsyncDevFuse::from_file(device.0)?;
        let file = Arc::new(async_device);
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.fuse_device = Some(file);
        self.auto_unmount_socket = sock
            .map(|sock| {
                sock.set_nonblocking(true)?;
                UnixStream::from_std(sock)
            })
            .transpose()?;
        self.unmount_tx = Some(tx);

        tokio::spawn(async {
            // Wait for unmount signal
            let Ok(mut mount) = rx.await else {
                warn!(
                    "Unmount signal channel closed, mounting may not have completed successfully",
                );
                return;
            };

            if let Err(err) = mount.umount_impl().await {
                error!(
                    "Failed to unmount filesystem at {:?}: {}",
                    mount.mountpoint, err
                );
            }
        });

        Ok(self)
    }

    /// Unmount the filesystem. This is a no-op if the filesystem is already unmounted.
    pub(crate) async fn umount_impl(&mut self) -> io::Result<()> {
        // Prevent unmount race (no-op)
        if let Some(fuse_device) = &self.fuse_device {
            if !is_mounted_async(fuse_device).await {
                return Ok(());
            }
        }

        // If fuse_device is not set, it means the mount was done via fusermount with auto unmount.
        // In this case, we can just drop the auto_unmount_socket to trigger unmount.
        if let Some(sock) = self.auto_unmount_socket.take() {
            drop(sock);
        }

        let mountpoint = self.mountpoint.clone();
        tokio::task::spawn_blocking(move || {
            // Attempt to unmount directly first, since it's more efficient. If it
            // fails with EPERM, then fallback to fusermount.
            if nix::unistd::getuid().is_root() {
                crate::mnt::libc_umount(&mountpoint).map_err(io::Error::from)?;
                return Ok(());
            }
            fuse_pure::fuse_unmount_pure(&mountpoint);
            Ok(())
        })
        .await
        .map_err(|_err| io::Error::other("blocking task panicked"))?
    }

    /// Unmount the filesystem. This is a no-op if the filesystem is already unmounted.
    pub(crate) fn umount_impl_sync(mut self) -> io::Result<()> {
        if let Some(tx) = self.unmount_tx.take() {
            // Signal the async unmount task to proceed with unmounting.
            let _ = tx.send(self);
        } else {
            warn!(
                "unmount tx not found for {:?}, mounting may not have completed successfully",
                self.mountpoint
            );
        }

        Ok(())
    }

    /// Get a reference to the underlying [`AsyncDevFuse`]. This will return `None` if the
    /// filesystem is not yet mounted.
    pub(crate) fn dev_fuse(&self) -> Option<&Arc<AsyncDevFuse>> {
        self.fuse_device.as_ref()
    }
}
