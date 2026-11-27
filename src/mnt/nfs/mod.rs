//! Experimental macOS mount backend: mount through macOS's own NFS client, without macFUSE.
//!
//! The session talks FUSE as it always does, but over an in-process [`transport`] rather than
//! `/dev/fuse`. On the other side of it is an NFSv3 server of its own, answering only
//! 127.0.0.1: [`rpc`] takes the calls, [`nfs3`] answers each with FUSE requests, which
//! [`fuse`] sends as the kernel module would. `mount_nfs` mounts that server. The kernel thus
//! speaks NFS to this process, which speaks FUSE to the filesystem.
//!
//! Any local user can connect to the server, so it answers MNT only until the mount is in use,
//! and every file handle carries a key made up for the server. Without the handle MNT handed
//! out to the mount, no request can name a file.
//!
//! What NFS, or this server, does not carry is lost:
//! - Every request reaches the filesystem as the user who mounted it, and `ACCESS` grants
//!   whatever is asked, so permissions are only checked by the filesystem itself, against that
//!   user. Other local users who can reach the mount point act with the mounting user's rights.
//! - `fsync` reaches the filesystem when the client commits, which NFS clients also do on
//!   `close`.
//! - No extended attributes, locks beyond the client's own (`locallocks`) or notifications.
//!   Node ids are never forgotten, as NFS has no counterpart to `FUSE_FORGET`.

pub(crate) mod fuse;
#[cfg(all(fuser_mount_impl = "nfs", not(fuser_nfs_serve_only)))]
mod mount;
pub(crate) mod nfs3;
pub(crate) mod rpc;
#[cfg(fuser_nfs_serve_only)]
mod serve_only;
pub(crate) mod transport;
mod xdr;

#[cfg(all(fuser_mount_impl = "nfs", not(fuser_nfs_serve_only)))]
pub(crate) use mount::MountImpl;
#[cfg(fuser_nfs_serve_only)]
pub(crate) use serve_only::MountImpl;

use log::warn;

use crate::MountOption;

/// The `mount_nfs` options for a server on `port`.
///
/// Attribute and negative-name caching are off, as the filesystem may change behind the client's
/// back. Soft and interruptible, so that a session which stopped answering fails calls rather
/// than hanging them.
#[cfg_attr(
    any(not(fuser_mount_impl = "nfs"), fuser_nfs_serve_only),
    allow(dead_code)
)]
pub(crate) fn mount_nfs_options(options: &[MountOption], port: u16) -> Vec<String> {
    let mut opts: Vec<String> = [
        "vers=3",
        "tcp",
        &format!("port={port}"),
        &format!("mountport={port}"),
        // No lockd to talk to
        "locallocks",
        // Attributes come with listings, rather than by a LOOKUP for each entry
        "rdirplus",
        "actimeo=0",
        "nonegnamecache",
        "soft",
        "intr",
        // Keep Finder and Spotlight from crawling it
        "nobrowse",
    ]
    .map(String::from)
    .to_vec();
    for option in options {
        match option {
            MountOption::RO => opts.push("rdonly".to_string()),
            MountOption::NoDev => opts.push("nodev".to_string()),
            MountOption::NoSuid => opts.push("nosuid".to_string()),
            MountOption::NoExec => opts.push("noexec".to_string()),
            MountOption::NoAtime => opts.push("noatime".to_string()),
            MountOption::Sync => opts.push("sync".to_string()),
            // Passed through verbatim, so that any mount_nfs option can be given
            MountOption::CUSTOM(value) => opts.push(value.clone()),
            // Best effort: macOS unmounts a mount whose server has stopped answering for
            // this long, as it does once this process has gone
            MountOption::AutoUnmount => opts.push("deadtimeout=5".to_string()),
            // The defaults, or named in the mount table instead
            MountOption::RW
            | MountOption::Dev
            | MountOption::Suid
            | MountOption::Exec
            | MountOption::Atime
            | MountOption::Async
            | MountOption::FSName(_)
            | MountOption::Subtype(_) => {}
            MountOption::DefaultPermissions => warn!(
                "MountOption::DefaultPermissions is ignored by the NFS backend: \
                 macOS's NFS client leaves permission checks to the server"
            ),
            MountOption::DirSync => warn!("MountOption::DirSync is ignored by the NFS backend"),
        }
    }
    opts
}

/// The export to mount, which the mount table shows after "127.0.0.1:": the filesystem's name,
/// where it is one that needs no quoting
#[cfg_attr(not(fuser_mount_impl = "nfs"), allow(dead_code))]
pub(crate) fn export_name(options: &[MountOption]) -> String {
    options
        .iter()
        .rev()
        .find_map(|option| match option {
            MountOption::FSName(name)
                if !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) =>
            {
                Some(name.clone())
            }
            _ => None,
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod test;
