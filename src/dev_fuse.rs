use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

/// A newtype for `File` that represents the `/dev/fuse` device.
#[derive(Debug)]
pub(crate) struct DevFuse(pub(crate) File);

impl AsRawFd for DevFuse {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for DevFuse {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl DevFuse {
    pub(crate) const PATH: &'static str = "/dev/fuse";

    #[allow(dead_code)] // Not used with every feature.
    pub(crate) fn open() -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(Self::PATH)
            .map(Self)
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

/// Name the device, so that "No such file or directory" says which file. The error kind is
/// preserved for callers that match on it
#[allow(dead_code)] // Not used with every feature.
fn open_error(err: io::Error) -> io::Error {
    if err.kind() == io::ErrorKind::NotFound {
        io::Error::new(
            err.kind(),
            format!("{} not found{MISSING_HINT}", DevFuse::PATH),
        )
    } else {
        io::Error::new(err.kind(), format!("opening {}: {err}", DevFuse::PATH))
    }
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
    }
}
