//! Experimental macOS mount backend: mount through macOS's own NFS client, without macFUSE.
//!
//! The session talks FUSE as it always does, but over an in-process [`transport`] rather than
//! `/dev/fuse`. On the other side of it is an NFS server of its own, answering only
//! 127.0.0.1: [`rpc`] takes the calls, [`nfs3`] or [`nfs4`] answers each with FUSE requests,
//! which [`fuse`] sends as the kernel module would. `mount_nfs` mounts that server. The kernel thus
//! speaks NFS to this process, which speaks FUSE to the filesystem.
//!
//! Any local user can connect to the server. The export's path holds a secret made up for the
//! server, which the mount table shows only once the mount is in use, and from then on the
//! server hands out no handle (MNT) and takes no new client (NFSv4.1). Every file handle
//! carries a key made up for the server too, and v4.1's client and session ids are random: so
//! no request but the mount's can name a file.
//!
//! Each call's AUTH_SYS credentials are passed on as the FUSE request's uid and gid, so the
//! filesystem checks permissions against the user who made the call, and `ACCESS` asks it
//! with `FUSE_ACCESS`. What NFS, or this server, does not carry is lost:
//! - Supplementary groups: a FUSE request names one group.
//! - `fsync` reaches the filesystem when the client commits, which NFS clients also do on
//!   `close`.
//! - No extended attributes or notifications. With NFSv3, locks stay in the client
//!   (`locallocks`) and opens do not reach the filesystem.
//! - Node ids are never forgotten. NFS has no counterpart to `FUSE_FORGET`, and a file handle
//!   is only a node id: were it forgotten, the filesystem could give the id to a new file,
//!   which a client holding the old handle would then reach.
//!
//! Experimentally, `MountOption::CUSTOM("vers=4")` mounts with NFSv4.1 instead, answered by
//! [`nfs4`]. Then OPEN and CLOSE reach the filesystem as open and release, locks as getlk and
//! setlk, and the session's reply cache keeps retransmissions from being run twice. NFSv3's
//! MNT is then refused, and v4's export can only be looked up until the mount is made.
//! macOS's v4 client cannot send owner or group 0 while it maps ids through its identity
//! service (`vfs.generic.nfs.client.idmap_ctrl` 1, the default): chown to root fails with
//! ENOSPC before any request is made. With `idmap_ctrl` 0 it sends "root" and "wheel", which
//! this server looks up.

pub(crate) mod fuse;
#[cfg(all(fuser_mount_impl = "nfs", not(fuser_nfs_serve_only)))]
mod mount;
pub(crate) mod nfs3;
pub(crate) mod nfs4;
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

/// NFSv3's write size. On mac-ci, 256 MiB written at 32 KiB went at 39 MiB/s, at 128 KiB 173
/// and at 512 KiB 433, but at 1 MiB macOS stalled the writer for 15 to 30 s at a time, after
/// each 64 MiB or so, for 2 MiB/s in all. NFSv4.1 does not.
const V3_WSIZE: u32 = 512 * 1024;

/// The `mount_nfs` options for a server on `port`.
///
/// Attributes are cached for a second, as FUSE does by default: with none cached, each
/// operation costs the client several calls to revalidate every directory on the way.
/// `MountOption::CUSTOM("actimeo=0")` turns it off, for a filesystem that changes behind the
/// client's back. Missing names are not cached. Soft and interruptible, so that a session which
/// stopped answering fails calls rather than hanging them.
#[cfg_attr(
    any(not(fuser_mount_impl = "nfs"), fuser_nfs_serve_only),
    allow(dead_code)
)]
pub(crate) fn mount_nfs_options(options: &[MountOption], port: u16) -> Vec<String> {
    let v4 = wants_v4(options);
    let mut opts: Vec<String> = if v4 {
        // No MOUNT program, and locks are the server's
        vec![
            "vers=4.1".to_string(),
            "tcp".to_string(),
            format!("port={port}"),
        ]
    } else {
        [
            "vers=3",
            "tcp",
            &format!("port={port}"),
            &format!("mountport={port}"),
            // No lockd to talk to
            "locallocks",
            // Attributes come with listings, rather than by a LOOKUP for each entry
            "rdirplus",
        ]
        .map(String::from)
        .to_vec()
    };
    opts.extend(
        [
            // Reads as large as the server takes, rather than the client's 32 KiB
            &format!("rsize={}", nfs3::MAX_IO),
            // Writes too, but for V3_WSIZE
            &format!("wsize={}", if v4 { nfs3::MAX_IO } else { V3_WSIZE }),
            "actimeo=1",
            "nonegnamecache",
            "soft",
            "intr",
            // Keep Finder and Spotlight from crawling it
            "nobrowse",
        ]
        .map(String::from),
    );
    for option in options {
        match option {
            MountOption::RO => {
                opts.push("rdonly".to_string());
                // Soft read-only mounts get locallocks by default, which NFSv4 refuses
                if wants_v4(options) {
                    opts.push("nolocallocks".to_string());
                }
            }
            MountOption::NoDev => opts.push("nodev".to_string()),
            MountOption::NoSuid => opts.push("nosuid".to_string()),
            MountOption::NoExec => opts.push("noexec".to_string()),
            MountOption::NoAtime => opts.push("noatime".to_string()),
            MountOption::Sync => opts.push("sync".to_string()),
            // The version is chosen above
            MountOption::CUSTOM(value) if is_v4(value) => {}
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

/// Whether the options ask for NFSv4, with `MountOption::CUSTOM("vers=4")` or `"vers=4.1"`,
/// rather than NFSv3. Experimental; the minor version is always 1
pub(crate) fn wants_v4(options: &[MountOption]) -> bool {
    options
        .iter()
        .any(|option| matches!(option, MountOption::CUSTOM(value) if is_v4(value)))
}

fn is_v4(value: &str) -> bool {
    matches!(value, "vers=4" | "vers=4.1" | "nfsvers=4" | "nfsvers=4.1")
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
