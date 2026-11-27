//! For testing with other NFS clients: serve the session, and leave mounting to someone else.
//!
//! Built with `FUSER_NFS_SERVE_ONLY` set, as CI does to test the server with Linux's NFS client.
//! The server listens on 127.0.0.1, on the port `FUSER_NFS_PORT` names, until the mount is
//! dropped or the process ends.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use log::error;
use log::info;

use super::fuse::Fuse;
use super::nfs3::Nfs;
use super::rpc::Server;
use super::rpc::Stopper;
use super::transport::Caller;
use super::transport::Transport;
use crate::MountOption;
use crate::SessionACL;
use crate::dev_fuse::DevFuse;

#[derive(Debug)]
pub(crate) struct MountImpl {
    fuse: Fuse,
    stopper: Stopper,
    server: Option<JoinHandle<()>>,
}

impl MountImpl {
    pub(crate) fn new(
        _mountpoint: &Path,
        options: &[MountOption],
        _acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let port = std::env::var("FUSER_NFS_PORT")
            .ok()
            .and_then(|port| port.parse().ok())
            .ok_or_else(|| io::Error::other("FUSER_NFS_PORT names no port to serve NFS on"))?;
        let transport = Arc::new(Transport::default());
        let device = Arc::new(DevFuse::from_transport(transport.clone())?);
        let caller = Caller {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        };
        let fuse = Fuse::new(transport, caller);
        let export = super::export_name(options);
        let read_only = options.contains(&MountOption::RO);
        let server = Server::bind(Nfs::new(fuse.clone(), read_only, &export)?, port)?;
        let stopper = server.stopper()?;
        let init = fuse.start_init().map_err(io::Error::from_raw_os_error)?;
        let initializing = fuse.clone();
        std::thread::Builder::new()
            .name("fuser-nfs-init".to_string())
            .spawn(move || match initializing.finish_init(&init) {
                Ok(()) => initializing.release_idle_forever(),
                Err(errno) => error!("FUSE_INIT failed: {}", io::Error::from_raw_os_error(errno)),
            })?;
        let server = std::thread::Builder::new()
            .name("fuser-nfs-server".to_string())
            .spawn(move || server.run())?;
        info!("Serving NFS on 127.0.0.1:{port}, export /{export}, for another client to mount");
        Ok((
            device,
            MountImpl {
                fuse,
                stopper,
                server: Some(server),
            },
        ))
    }

    /// Nothing is mounted here
    pub(crate) fn wait_mounted(&self) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        self.fuse.shutdown();
        self.stopper.stop();
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        Ok(())
    }
}
