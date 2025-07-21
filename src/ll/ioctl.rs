//! This module contains functions for interacting with the FUSE device through ioctls.
// TODO: fix all these non camel case types
#![allow(non_camel_case_types)]

use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::Arc;

// The `fuse_backing_map_out` struct is used to pass information about a backing file
// descriptor to the kernel.
#[repr(C)]
pub struct fuse_backing_map_out {
    pub fd: u32,
    pub flags: u32,
    pub padding: u64,
}

const FUSE_DEV_IOC_MAGIC: u8 = 229;
const FUSE_DEV_IOC_BACKING_OPEN: u8 = 1;
const FUSE_DEV_IOC_BACKING_CLOSE: u8 = 2;

// This ioctl is used to register a backing file descriptor with the kernel.
// The kernel will return a backing ID that can be used to refer to the file descriptor in
// subsequent operations.
nix::ioctl_write_ptr!(
    fuse_dev_ioc_backing_open,
    FUSE_DEV_IOC_MAGIC,
    FUSE_DEV_IOC_BACKING_OPEN,
    fuse_backing_map_out
);

// This ioctl is used to deregister a backing file descriptor.
nix::ioctl_write_ptr!(
    fuse_dev_ioc_backing_close,
    FUSE_DEV_IOC_MAGIC,
    FUSE_DEV_IOC_BACKING_CLOSE,
    u32
);

pub(crate) fn ioctl_open_backing(
        channel: &Arc<File>,
        fd: u32,
    ) -> std::io::Result<u32> {
    let map = fuse_backing_map_out {
        fd,
        flags: 0,
        padding: 0,
    };
    let id = unsafe { fuse_dev_ioc_backing_open(channel.as_raw_fd(), &map) }
    ?;
    Ok(id as u32)
}

pub(crate) fn ioctl_close_backing(
        channel: &Arc<File>,
        backing_id: u32,
    ) -> std::io::Result<u32> {
    let code = unsafe { fuse_dev_ioc_backing_close(channel.as_raw_fd(), &backing_id) }
    ?;
    Ok(code as u32)
}