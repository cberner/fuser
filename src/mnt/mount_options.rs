use std::collections::HashSet;
use std::ffi::OsStr;
use std::io;
use std::io::ErrorKind;

use crate::SessionACL;

/// Fuser session configuration, including mount options.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Config {
    /// Mount options.
    pub mount_options: Vec<MountOption>,
    /// Who can access the filesystem.
    pub acl: SessionACL,
    /// Number of event loop threads. If unspecified, one thread is used.
    pub n_threads: Option<usize>,
    /// Use `FUSE_DEV_IOC_CLONE` to give each worker thread its own fd.
    /// This enables more efficient request processing
    /// when multiple threads are used. Requires Linux 4.5+.
    pub clone_fd: bool,
}

/// Mount options accepted by the FUSE filesystem type
/// See 'man mount.fuse' for details
// TODO: add all options that 'man mount.fuse' documents and libfuse supports
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum MountOption {
    /// Set the name of the source in mtab
    FSName(String),
    /// Set the filesystem subtype in mtab
    Subtype(String),
    /// Allows passing an option which is not otherwise supported in these enums
    #[allow(clippy::upper_case_acronyms)]
    CUSTOM(String),

    /* Parameterless options */
    /// Automatically unmount when the mounting process exits
    ///
    /// `AutoUnmount` requires `AllowOther` or `AllowRoot`. If `AutoUnmount` is set and neither `Allow...` is set, the FUSE configuration must permit `allow_other`, otherwise mounting will fail.
    AutoUnmount,
    /// Enable permission checking in the kernel
    DefaultPermissions,

    /* Flags */
    /// Enable special character and block devices
    Dev,
    /// Disable special character and block devices
    NoDev,
    /// Honor set-user-id and set-groupd-id bits on files
    Suid,
    /// Don't honor set-user-id and set-groupd-id bits on files
    NoSuid,
    /// Read-only filesystem
    RO,
    /// Read-write filesystem
    RW,
    /// Allow execution of binaries
    Exec,
    /// Don't allow execution of binaries
    NoExec,
    /// Support inode access time
    Atime,
    /// Don't update inode access time
    NoAtime,
    /// All modifications to directories will be done synchronously
    DirSync,
    /// All I/O will be done synchronously
    Sync,
    /// All I/O will be done asynchronously
    Async,
    /* libfuse library options, such as "direct_io", are not included since they are specific
    to libfuse, and not part of the kernel ABI */
}

#[cfg_attr(
    all(fuser_mount_impl = "direct-mount", fuser_mount_impl = "macos-no-mount"),
    expect(dead_code)
)]
#[derive(PartialEq)]
pub(crate) enum MountOptionGroup {
    KernelOption,
    KernelFlag,
    Fusermount,
}

impl MountOption {
    pub(crate) fn from_str(s: &str) -> MountOption {
        match s {
            "auto_unmount" => MountOption::AutoUnmount,
            "default_permissions" => MountOption::DefaultPermissions,
            "dev" => MountOption::Dev,
            "nodev" => MountOption::NoDev,
            "suid" => MountOption::Suid,
            "nosuid" => MountOption::NoSuid,
            "ro" => MountOption::RO,
            "rw" => MountOption::RW,
            "exec" => MountOption::Exec,
            "noexec" => MountOption::NoExec,
            "atime" => MountOption::Atime,
            "noatime" => MountOption::NoAtime,
            "dirsync" => MountOption::DirSync,
            "sync" => MountOption::Sync,
            "async" => MountOption::Async,
            x if x.starts_with("fsname=") => MountOption::FSName(x[7..].into()),
            x if x.starts_with("subtype=") => MountOption::Subtype(x[8..].into()),
            x => MountOption::CUSTOM(x.into()),
        }
    }
}

pub(crate) fn check_option_conflicts(options: &Config) -> Result<(), io::Error> {
    let mut options_set = HashSet::new();
    options_set.extend(options.mount_options.iter().cloned());
    let conflicting: HashSet<MountOption> = options
        .mount_options
        .iter()
        .flat_map(conflicts_with)
        .collect();
    let intersection: Vec<MountOption> = conflicting.intersection(&options_set).cloned().collect();
    if intersection.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Conflicting mount options found: {intersection:?}"),
        ))
    }
}

fn conflicts_with(option: &MountOption) -> Vec<MountOption> {
    match option {
        MountOption::FSName(_)
        | MountOption::Subtype(_)
        | MountOption::CUSTOM(_)
        | MountOption::DirSync
        | MountOption::AutoUnmount
        | MountOption::DefaultPermissions => vec![],
        MountOption::Dev => vec![MountOption::NoDev],
        MountOption::NoDev => vec![MountOption::Dev],
        MountOption::Suid => vec![MountOption::NoSuid],
        MountOption::NoSuid => vec![MountOption::Suid],
        MountOption::RO => vec![MountOption::RW],
        MountOption::RW => vec![MountOption::RO],
        MountOption::Exec => vec![MountOption::NoExec],
        MountOption::NoExec => vec![MountOption::Exec],
        MountOption::Atime => vec![MountOption::NoAtime],
        MountOption::NoAtime => vec![MountOption::Atime],
        MountOption::Sync => vec![MountOption::Async],
        MountOption::Async => vec![MountOption::Sync],
    }
}

// Format option to be passed to libfuse or kernel
#[allow(dead_code)]
pub(crate) fn option_to_string(option: &MountOption) -> String {
    match option {
        MountOption::FSName(name) => format!("fsname={name}"),
        MountOption::Subtype(subtype) => format!("subtype={subtype}"),
        MountOption::CUSTOM(value) => value.to_string(),
        MountOption::AutoUnmount => "auto_unmount".to_string(),
        MountOption::DefaultPermissions => "default_permissions".to_string(),
        MountOption::Dev => "dev".to_string(),
        MountOption::NoDev => "nodev".to_string(),
        MountOption::Suid => "suid".to_string(),
        MountOption::NoSuid => "nosuid".to_string(),
        MountOption::RO => "ro".to_string(),
        MountOption::RW => "rw".to_string(),
        MountOption::Exec => "exec".to_string(),
        MountOption::NoExec => "noexec".to_string(),
        MountOption::Atime => "atime".to_string(),
        MountOption::NoAtime => "noatime".to_string(),
        MountOption::DirSync => "dirsync".to_string(),
        MountOption::Sync => "sync".to_string(),
        MountOption::Async => "async".to_string(),
    }
}

#[cfg_attr(
    not(any(
        fuser_mount_impl = "pure-rust",
        any(
            fuser_mount_impl = "direct-mount",
            not(fuser_mount_impl = "macos-no-mount")
        ),
    )),
    expect(dead_code)
)]
pub(crate) fn option_group(option: &MountOption) -> MountOptionGroup {
    match option {
        MountOption::FSName(_) => MountOptionGroup::Fusermount,
        MountOption::Subtype(_) => MountOptionGroup::Fusermount,
        MountOption::CUSTOM(_) => MountOptionGroup::KernelOption,
        MountOption::AutoUnmount => MountOptionGroup::Fusermount,
        MountOption::Dev => MountOptionGroup::KernelFlag,
        MountOption::NoDev => MountOptionGroup::KernelFlag,
        MountOption::Suid => MountOptionGroup::KernelFlag,
        MountOption::NoSuid => MountOptionGroup::KernelFlag,
        MountOption::RO => MountOptionGroup::KernelFlag,
        MountOption::RW => MountOptionGroup::KernelFlag,
        MountOption::Exec => MountOptionGroup::KernelFlag,
        MountOption::NoExec => MountOptionGroup::KernelFlag,
        MountOption::Atime => MountOptionGroup::KernelFlag,
        MountOption::NoAtime => MountOptionGroup::KernelFlag,
        MountOption::DirSync => MountOptionGroup::KernelFlag,
        MountOption::Sync => MountOptionGroup::KernelFlag,
        MountOption::Async => MountOptionGroup::KernelFlag,
        MountOption::DefaultPermissions => MountOptionGroup::KernelOption,
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(
    not(any(
        fuser_mount_impl = "macos-no-mount",
        fuser_mount_impl = "pure-rust",
        fuser_mount_impl = "direct-mount",
    )),
    expect(dead_code)
)]
pub(crate) fn option_to_flag(option: &MountOption) -> io::Result<nix::mount::MsFlags> {
    match option {
        MountOption::Dev => Ok(nix::mount::MsFlags::empty()), // There is no option for dev. It's the absence of NoDev
        MountOption::NoDev => Ok(nix::mount::MsFlags::MS_NODEV),
        MountOption::Suid => Ok(nix::mount::MsFlags::empty()),
        MountOption::NoSuid => Ok(nix::mount::MsFlags::MS_NOSUID),
        MountOption::RW => Ok(nix::mount::MsFlags::empty()),
        MountOption::RO => Ok(nix::mount::MsFlags::MS_RDONLY),
        MountOption::Exec => Ok(nix::mount::MsFlags::empty()),
        MountOption::NoExec => Ok(nix::mount::MsFlags::MS_NOEXEC),
        MountOption::Atime => Ok(nix::mount::MsFlags::empty()),
        MountOption::NoAtime => Ok(nix::mount::MsFlags::MS_NOATIME),
        MountOption::Async => Ok(nix::mount::MsFlags::empty()),
        MountOption::Sync => Ok(nix::mount::MsFlags::MS_SYNCHRONOUS),
        MountOption::DirSync => Ok(nix::mount::MsFlags::MS_DIRSYNC),
        option => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid mount option for flag conversion: {option:?}"),
        )),
    }
}

#[cfg(target_os = "macos")]
#[expect(dead_code)]
pub(crate) fn option_to_flag(option: &MountOption) -> io::Result<nix::mount::MntFlags> {
    match option {
        MountOption::Dev => Ok(nix::mount::MntFlags::empty()), // There is no option for dev. It's the absence of NoDev
        MountOption::NoDev => Ok(nix::mount::MntFlags::MNT_NODEV),
        MountOption::Suid => Ok(nix::mount::MntFlags::empty()),
        MountOption::NoSuid => Ok(nix::mount::MntFlags::MNT_NOSUID),
        MountOption::RW => Ok(nix::mount::MntFlags::empty()),
        MountOption::RO => Ok(nix::mount::MntFlags::MNT_RDONLY),
        MountOption::Exec => Ok(nix::mount::MntFlags::empty()),
        MountOption::NoExec => Ok(nix::mount::MntFlags::MNT_NOEXEC),
        MountOption::Atime => Ok(nix::mount::MntFlags::empty()),
        MountOption::NoAtime => Ok(nix::mount::MntFlags::MNT_NOATIME),
        MountOption::Async => Ok(nix::mount::MntFlags::empty()),
        MountOption::Sync => Ok(nix::mount::MntFlags::MNT_SYNCHRONOUS),
        option => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid mount option for flag conversion: {option:?}"),
        )),
    }
}

#[cfg_attr(
    any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ),
    allow(dead_code)
)]
#[cfg(any(
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub(crate) fn option_to_flag(option: &MountOption) -> io::Result<nix::mount::MntFlags> {
    match option {
        MountOption::Dev => Ok(nix::mount::MntFlags::empty()),
        #[cfg(target_os = "freebsd")]
        MountOption::NoDev => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NoDev option is not supported on FreeBSD",
        )),
        #[cfg(not(target_os = "freebsd"))]
        MountOption::NoDev => Ok(nix::mount::MntFlags::MNT_NODEV),
        MountOption::Suid => Ok(nix::mount::MntFlags::empty()),
        MountOption::NoSuid => Ok(nix::mount::MntFlags::MNT_NOSUID),
        MountOption::RW => Ok(nix::mount::MntFlags::empty()),
        MountOption::RO => Ok(nix::mount::MntFlags::MNT_RDONLY),
        MountOption::Exec => Ok(nix::mount::MntFlags::empty()),
        MountOption::NoExec => Ok(nix::mount::MntFlags::MNT_NOEXEC),
        MountOption::Atime => Ok(nix::mount::MntFlags::empty()),
        MountOption::NoAtime => Ok(nix::mount::MntFlags::MNT_NOATIME),
        MountOption::Async => Ok(nix::mount::MntFlags::MNT_ASYNC),
        MountOption::Sync => Ok(nix::mount::MntFlags::MNT_SYNCHRONOUS),
        MountOption::DirSync => Ok(nix::mount::MntFlags::MNT_SYNCHRONOUS),
        option => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid mount option for flag conversion: {option:?}"),
        )),
    }
}

/// Parses mount command args.
///
/// Input: `"-o", "suid", "-o", "ro,nodev,noexec", "-osync"`
/// Output Ok([`Suid`, `RO`, `NoDev`, `NoExec`, `Sync`])
pub(crate) fn parse_options_from_args(args: &[&OsStr]) -> io::Result<Config> {
    let err = |x| io::Error::new(ErrorKind::InvalidInput, x);
    let args: Option<Vec<_>> = args.iter().map(|x| x.to_str()).collect();
    let args = args.ok_or_else(|| err("Error parsing args: Invalid UTF-8".to_owned()))?;
    let mut it = args.iter();
    let mut out = vec![];
    let mut acl = None;
    loop {
        let opt = match it.next() {
            None => break,
            Some(&"-o") => *it.next().ok_or_else(|| {
                err("Error parsing args: Expected option, reached end of args".to_owned())
            })?,
            Some(x) if x.starts_with("-o") => &x[2..],
            Some(x) => return Err(err(format!("Error parsing args: expected -o, got {x}"))),
        };
        for x in opt.split(',') {
            match x {
                "allow_root" => {
                    if acl.is_some() {
                        return Err(err(
                            "allow_root option conflicts with previous ACL".to_owned()
                        ));
                    }
                    acl = Some(SessionACL::RootAndOwner);
                }
                "allow_other" => {
                    if acl.is_some() {
                        return Err(err(
                            "allow_other option conflicts with previous ACL".to_owned()
                        ));
                    }
                    acl = Some(SessionACL::All);
                }
                x => {
                    out.push(MountOption::from_str(x));
                }
            }
        }
    }
    let acl = acl.unwrap_or(SessionACL::default());
    Ok(Config {
        mount_options: out,
        acl,
        n_threads: None,
        clone_fd: false,
    })
}

#[cfg(test)]
mod test {
    use std::os::unix::prelude::OsStrExt;

    use crate::mnt::mount_options::*;

    #[test]
    fn option_checking() {
        assert!(
            check_option_conflicts(&Config {
                mount_options: vec![MountOption::Suid, MountOption::NoSuid],
                ..Config::default()
            })
            .is_err()
        );
        assert!(
            check_option_conflicts(&Config {
                mount_options: vec![MountOption::Suid, MountOption::NoExec],
                ..Config::default()
            })
            .is_ok()
        );
    }
    #[test]
    fn option_round_trip() {
        use crate::mnt::mount_options::MountOption::*;
        for x in &[
            FSName("Blah".to_owned()),
            Subtype("Bloo".to_owned()),
            CUSTOM("bongos".to_owned()),
            AutoUnmount,
            DefaultPermissions,
            Dev,
            NoDev,
            Suid,
            NoSuid,
            RO,
            RW,
            Exec,
            NoExec,
            Atime,
            NoAtime,
            DirSync,
            Sync,
            Async,
        ] {
            assert_eq!(*x, MountOption::from_str(option_to_string(x).as_ref()));
        }
    }

    #[test]
    fn test_parse_options() {
        use crate::mnt::mount_options::MountOption::*;

        assert_eq!(parse_options_from_args(&[]).unwrap(), Config::default());

        let o: Vec<_> = "-o suid -o ro,nodev,noexec -osync"
            .split(' ')
            .map(OsStr::new)
            .collect();
        let out = parse_options_from_args(o.as_ref()).unwrap();
        assert_eq!(
            out,
            Config {
                mount_options: vec![Suid, RO, NoDev, NoExec, Sync],
                ..Config::default()
            }
        );

        assert!(parse_options_from_args(&[OsStr::new("-o")]).is_err());
        assert!(parse_options_from_args(&[OsStr::new("not o")]).is_err());
        assert!(parse_options_from_args(&[OsStr::from_bytes(b"-o\xc3\x28")]).is_err());
    }
}
