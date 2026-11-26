use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

/// The kernel connection of a mount: the `/dev/fuse` device, or on macOS an MFMount channel
/// or the in-process connection to the NFS backend.
#[derive(Debug)]
pub(crate) struct DevFuse {
    /// For a connection without an fd, a placeholder that is not connected to it
    file: File,
    #[cfg(fuser_macfuse_fskit)]
    pub(crate) mf_channel: Option<crate::mnt::mfmount::MfChannel>,
    #[cfg(any(fuser_mount_impl = "nfs", test))]
    pub(crate) transport: Option<std::sync::Arc<crate::mnt::nfs::transport::Transport>>,
}

impl AsRawFd for DevFuse {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.file.as_raw_fd()
    }
}

impl AsFd for DevFuse {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl DevFuse {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(fuser_macfuse_fskit)]
            mf_channel: None,
            #[cfg(any(fuser_mount_impl = "nfs", test))]
            transport: None,
        }
    }

    /// A connection within the process, to the NFS backend's server
    #[cfg(any(fuser_mount_impl = "nfs", test))]
    pub(crate) fn from_transport(
        transport: std::sync::Arc<crate::mnt::nfs::transport::Transport>,
    ) -> io::Result<Self> {
        Ok(Self {
            transport: Some(transport),
            ..Self::new(File::open("/dev/null")?)
        })
    }

    #[cfg(all(test, fuser_mount_impl = "pure-rust"))]
    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    /// A connection over macFUSE's FSKit backend
    #[cfg(fuser_macfuse_fskit)]
    pub(crate) fn from_mf_channel(channel: crate::mnt::mfmount::MfChannel) -> io::Result<Self> {
        Ok(Self {
            mf_channel: Some(channel),
            ..Self::new(File::open("/dev/null")?)
        })
    }

    pub(crate) const PATH: &'static str = "/dev/fuse";

    #[allow(dead_code)] // Not used with every feature.
    pub(crate) fn open() -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(Self::PATH)
            .map(Self::new)
            .map_err(open_error)
    }
}

/// How the device is provided, and so what to try when it is missing, differs per target
#[cfg(target_os = "linux")]
const MISSING_HINT: &str = ", try 'modprobe fuse'";
#[cfg(target_os = "freebsd")]
const MISSING_HINT: &str = ", try 'kldload fusefs'";
#[cfg(target_os = "macos")]
const MISSING_HINT: &str = "; is macFUSE installed?";
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
const MISSING_HINT: &str = "";

/// Name the device, so that "No such file or directory" says which file
#[allow(dead_code)] // Not used with every feature.
fn open_error(err: io::Error) -> io::Error {
    let message = if err.kind() == io::ErrorKind::NotFound {
        format!("{} not found{MISSING_HINT}", DevFuse::PATH)
    } else {
        format!("opening {}: {err}", DevFuse::PATH)
    };
    crate::mnt::with_message(err, message)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Opening the FUSE device cannot be made to fail on demand, so check the reporting
    /// itself: which file is missing, and how to get it, must both survive
    #[test]
    fn open_failures_name_the_device() {
        let err = open_error(io::ErrorKind::NotFound.into());
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains(DevFuse::PATH), "{err}");
        // The BSDs load a differently named module, and macOS none at all, so advice
        // for one target must not reach another
        #[cfg(target_os = "linux")]
        assert!(err.to_string().contains("modprobe fuse"), "{err}");
        #[cfg(not(target_os = "linux"))]
        assert!(!err.to_string().contains("modprobe"), "{err}");

        // Anything else is reported as it came, with the device named
        let err = open_error(io::ErrorKind::PermissionDenied.into());
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains(DevFuse::PATH), "{err}");
        // Advice for getting the device belongs only on the branch where it is absent
        assert!(!err.to_string().contains("not found"), "{err}");

        // The OS error number is what callers match on, so it is kept
        for errno in [libc::ENOENT, libc::EACCES, libc::EPERM] {
            let err = open_error(io::Error::from_raw_os_error(errno));
            assert_eq!(err.raw_os_error(), Some(errno));
        }
    }
}
