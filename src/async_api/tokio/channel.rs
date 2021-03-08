//! FUSE kernel driver communication
//!
//! Raw communication channel to the FUSE kernel driver.

#[cfg(any(feature = "libfuse", test))]
#[cfg(feature = "libfuse2")]
use crate::fuse_sys::fuse_mount_compat25;
#[cfg(not(feature = "libfuse"))]
use crate::fuse_sys::fuse_mount_pure;
#[cfg(feature = "libfuse3")]
use crate::fuse_sys::{fuse_session_fd, fuse_session_mount, fuse_session_new};

use libc::{self, c_void};
use log::error;
use log::warn;
#[cfg(any(feature = "libfuse", test))]
use std::ffi::OsStr;
use std::{os::unix::io::IntoRawFd, time::Duration};

#[cfg(any(feature = "libfuse", test))]
use crate::channel::with_fuse_args;
use crate::{
    async_api::tokio::io_ops::{FileDescriptorRawHandle, SubChannel},
    channel::unmount,
};

#[cfg(feature = "libfuse")]
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{io, ptr};

#[cfg(all(feature = "libfuse", feature = "async_impl"))]
use std::os::unix::ffi::OsStrExt;

#[cfg(not(feature = "libfuse"))]
use crate::MountOption;

/// Flag to tell OS for fuse to clone the underlying handle so we can have more than one reference to a session.
#[cfg(target_os = "macos")]
pub const FUSE_DEV_IOC_CLONE: u64 = 0x_80_04_e5_00; // = _IOR(229, 0, uint32_t)

/// Flag to tell OS for fuse to clone the underlying handle so we can have more than one reference to a session.
#[cfg(target_os = "linux")]
pub const FUSE_DEV_IOC_CLONE: u64 = 0x_80_04_e5_00; // = _IOR(229, 0, uint32_t)

/// Flag to tell OS for fuse to clone the underlying handle so we can have more than one reference to a session.
#[cfg(target_os = "freebsd")]
pub const FUSE_DEV_IOC_CLONE: u64 = 0x_40_04_e5_00; // = _IOR(229, 0, uint32_t)

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug)]
pub struct Channel {
    mountpoint: PathBuf,
    pub(in crate) session_fd: Arc<SubChannel>,
    pub(in crate) sub_channels: Vec<Arc<SubChannel>>,
    pub(in crate) fuse_session: *mut c_void,
}

/// This is required since the fuse_sesion is an opaque ptr to the session
/// so rust is unable to infer that it is safe for send.
unsafe impl Send for Channel {}
unsafe impl Sync for Channel {}

impl Channel {
    /// This allows file systems to work concurrently over several buffers/descriptors for concurrent operation.
    /// More detailed description of the protocol is at:
    /// https://john-millikin.com/the-fuse-protocol#multi-threading
    ///
    #[cfg(not(target_os = "macos"))]
    fn create_worker(root_fd: &Arc<SubChannel>) -> io::Result<Arc<SubChannel>> {
        let fuse_device_name = "/dev/fuse";

        let fd = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(fuse_device_name)
        {
            Ok(file) => file.into_raw_fd(),
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    error!("{} not found. Try 'modprobe fuse'", fuse_device_name);
                }
                return Err(error);
            }
        };

        let code = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if code == -1 {
            error!("fcntl command failed with {}", code);
            return Err(io::Error::last_os_error());
        }

        let code = unsafe { libc::ioctl(fd, FUSE_DEV_IOC_CLONE, root_fd.as_raw_fd()) };
        if code == -1 {
            error!("Clone command failed with {}", code);
            return Err(io::Error::last_os_error());
        }

        Ok(Arc::new(SubChannel::new(
            FileDescriptorRawHandle::new(fd),
            Duration::from_millis(1000),
        )?))
    }

    // mac fuse seems to just re-use the root fd relying onthe atomic semantics setup in the driver
    // This will have lowerthroughput than the linux approach.
    #[cfg(target_os = "macos")]
    fn create_worker(root_fd: &Arc<SubChannel>) -> io::Result<Arc<SubChannel>> {
        Ok(root_fd.clone())
    }
    ///
    /// Create worker fd's takes the root/session file descriptor and makes several clones
    /// This allows file systems to work concurrently over several buffers/descriptors for concurrent operation.
    /// More detailed description of the protocol is at:
    /// https://john-millikin.com/the-fuse-protocol#multi-threading
    ///
    fn create_sub_channels(
        mountpoint: PathBuf,
        worker_channel_count: usize,
        root_fd: FileDescriptorRawHandle,
        fuse_session: *mut c_void,
    ) -> io::Result<Channel> {
        let mut worker_channels = Vec::default();

        let root_sub_channel = Arc::new(SubChannel::new(root_fd, Duration::from_millis(1))?);
        worker_channels.push(root_sub_channel.clone());

        for _ in 0..worker_channel_count {
            worker_channels.push(Channel::create_worker(&root_sub_channel)?);
        }

        Ok(Channel {
            mountpoint,
            sub_channels: worker_channels,
            session_fd: root_sub_channel,
            fuse_session,
        })
    }

    /// This is separated out here since the one method we call has multiple error exit points
    /// given any exit on error from the inner method we will do an unmount/cleanup step here.
    fn new_from_session_and_fd(
        mountpoint: &Path,
        worker_channel_count: usize,
        fd: FileDescriptorRawHandle,
        fuse_session: *mut c_void,
    ) -> io::Result<Channel> {
        // make a copy here for error handling if we lost it in attempting to construct the channel.
        let tmp_root_fd = fd.fd;
        match Channel::create_sub_channels(
            mountpoint.to_owned(),
            worker_channel_count,
            fd,
            fuse_session,
        ) {
            Ok(r) => Ok(r),
            Err(err) => {
                if let Err(e) = unmount(mountpoint, fuse_session, tmp_root_fd) {
                    warn!("When shutting down on error, attempted to unmount failed with error {:?}. Given failure to mount this maybe be fine.", e);
                };
                Err(err)
            }
        }
    }
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel. If the channel is dropped, the path is
    /// unmounted.
    #[cfg(feature = "libfuse2")]
    pub fn new(
        mountpoint: &Path,
        worker_channel_count: usize,
        options: &[&OsStr],
    ) -> io::Result<Channel> {
        let mountpoint = mountpoint.canonicalize()?;

        with_fuse_args(options, |args| {
            let mnt = CString::new(mountpoint.as_os_str().as_bytes())?;
            let fd = unsafe { fuse_mount_compat25(mnt.as_ptr(), args) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Channel::new_from_session_and_fd(
                &mountpoint,
                worker_channel_count,
                FileDescriptorRawHandle::new(fd),
                ptr::null_mut(),
            )
        })
    }

    #[cfg(feature = "libfuse3")]
    pub fn new(
        mountpoint: &Path,
        worker_channel_count: usize,
        options: &[&OsStr],
    ) -> io::Result<Channel> {
        let mountpoint = mountpoint.canonicalize()?;
        with_fuse_args(options, |args| {
            let mnt = CString::new(mountpoint.as_os_str().as_bytes())?;
            let fuse_session = unsafe { fuse_session_new(args, ptr::null(), 0, ptr::null_mut()) };
            if fuse_session.is_null() {
                return Err(io::Error::last_os_error());
            }
            let result = unsafe { fuse_session_mount(fuse_session, mnt.as_ptr()) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { fuse_session_fd(fuse_session) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Channel::new_from_session_and_fd(
                &mountpoint,
                worker_channel_count,
                FileDescriptorRawHandle::new(fd),
                fuse_session,
            )
        })
    }

    #[cfg(not(feature = "libfuse"))]
    pub fn new2(
        mountpoint: &Path,
        worker_channel_count: usize,
        options: &[MountOption],
    ) -> io::Result<Channel> {
        let mountpoint = mountpoint.canonicalize()?;

        let fd = fuse_mount_pure(mountpoint.as_os_str(), options)?;
        Channel::new_from_session_and_fd(
            &mountpoint,
            worker_channel_count,
            FileDescriptorRawHandle::new(fd),
            ptr::null_mut(),
        )
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        // TODO: send ioctl FUSEDEVIOCSETDAEMONDEAD on macOS before closing the fd
        // Close the communication channel to the kernel driver
        // (closing it before unnmount prevents sync unmount deadlock)

        // Close all the channel/file handles. This will include the session fd.
        for sub_channel in self.sub_channels.iter() {
            sub_channel.close()
        }

        // Unmount this channel's mount point
        self.fuse_session = ptr::null_mut(); // unmount frees this pointer
    }
}
