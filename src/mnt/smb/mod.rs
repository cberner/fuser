//! Experimental, macOS only: mount through macOS's own SMB client rather than macFUSE.
//!
//! No FUSE driver is involved. The session reads requests from an in-process [`transport`]
//! instead of `/dev/fuse`, and an SMB server inside the process makes them: it serves the
//! filesystem as a share on a loopback port, with a password made up for the mount, and
//! `mount_smbfs` mounts that share.
//!
//! The server is fuser's own, and serves SMB 2.1 only: [`server`] frames messages over TCP,
//! [`smb2`] answers each command, after [`ntlm`] has checked the logon, with FUSE requests
//! through a [`client`] that plays the kernel's part.
//!
//! All of it builds everywhere, for its tests; it mounts only on macOS, with the `macos-smb`
//! feature.

#[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
pub(crate) mod client;
#[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
mod convert;
#[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
mod crypto;
#[cfg(fuser_mount_impl = "smb")]
mod mount;
#[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
mod ntlm;
#[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
mod server;
#[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
mod smb2;
#[cfg(test)]
mod test;
pub(crate) mod transport;
#[cfg_attr(not(fuser_mount_impl = "smb"), allow(dead_code))]
mod wire;

#[cfg(fuser_mount_impl = "smb")]
pub(crate) use mount::MountImpl;
