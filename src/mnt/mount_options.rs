use std::collections::HashSet;
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
    ///
    /// On Linux the value may contain any character except NUL. On other platforms it may
    /// contain neither comma nor backslash, because the mount helpers there cannot escape them.
    FSName(String),
    /// Set the filesystem subtype in mtab
    ///
    /// The value may not contain NUL, comma, or backslash.
    Subtype(String),
    /// Allows passing an option which is not otherwise supported in these enums
    ///
    /// The value may not contain NUL, comma, or backslash.
    #[allow(clippy::upper_case_acronyms)]
    CUSTOM(String),

    /* Parameterless options */
    /// Automatically unmount when the mounting process exits
    ///
    /// Unmounting once that process is gone takes something that outlives it: normally the
    /// `fusermount` helper, or, on systems that ship no FUSE userspace, a watcher fuser
    /// forks itself, which takes the privilege to mount directly. With neither available
    /// the mount fails, rather than quietly not honouring the option.
    ///
    /// Requires a [`SessionACL`](crate::SessionACL) other than `SessionACL::Owner`, because
    /// the helper does its unmount as root, and a filesystem that admits only its owner
    /// refuses root the look at the mountpoint that decides whether to unmount.
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

impl MountOption {
    #[cfg(test)]
    fn from_str(s: &str) -> MountOption {
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

#[allow(dead_code)]
#[derive(PartialEq)]
pub(crate) enum MountOptionGroup {
    KernelOption,
    KernelFlag,
    Fusermount,
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

/// Option values reach the kernel, libfuse, or a fusermount helper inside a comma
/// separated list, so an unescaped comma in a value is read as the start of the next
/// option. libfuse and fusermount decode backslash escapes, but of the values fuser sends
/// them only `fsname` is re-escaped by libfuse when it forwards options to fusermount, so
/// every other value must be free of both characters. NUL terminates the list and can
/// never be represented.
pub(crate) fn check_option_values(options: &[MountOption]) -> Result<(), io::Error> {
    for option in options {
        match option {
            // Linux is the only platform where every consumer of fsname either takes it
            // verbatim (as the mount(2) source) or decodes the escapes added by
            // option_to_escaped_string
            MountOption::FSName(name) if cfg!(any(target_os = "linux", target_os = "android")) => {
                check_option_value(option, name, &['\0'])?;
            }
            MountOption::FSName(value)
            | MountOption::Subtype(value)
            | MountOption::CUSTOM(value) => {
                check_option_value(option, value, &['\0', ',', '\\'])?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn check_option_value(
    option: &MountOption,
    value: &str,
    invalid: &[char],
) -> Result<(), io::Error> {
    match value.chars().find(|c| invalid.contains(c)) {
        Some(c) => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Mount option {option:?} contains an invalid character: {c:?}"),
        )),
        None => Ok(()),
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

// Format option to be passed to libfuse or a fusermount helper, both of which split the
// option list on commas and decode backslash escapes, unlike the kernel, which takes
// option values verbatim
#[allow(dead_code)]
pub(crate) fn option_to_escaped_string(option: &MountOption) -> String {
    match option {
        // fsname is the only value allowed to contain characters that need escaping,
        // see check_option_values()
        MountOption::FSName(name) => format!("fsname={}", escape_option_value(name)),
        option => option_to_string(option),
    }
}

fn escape_option_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        if c == ',' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

#[allow(dead_code)]
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

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(dead_code)]
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
#[allow(dead_code)]
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

#[cfg(test)]
mod test {
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
    fn option_value_checking() {
        use crate::mnt::mount_options::MountOption::*;

        for option in [FSName, Subtype, CUSTOM] {
            assert!(check_option_values(&[option("no\0name".to_owned())]).is_err());
        }
        for option in [Subtype, CUSTOM] {
            assert!(check_option_values(&[option("comma,injected".to_owned())]).is_err());
            assert!(check_option_values(&[option("back\\slash".to_owned())]).is_err());
        }
        // Only on Linux can fsname be escaped everywhere it is used
        assert_eq!(
            check_option_values(&[FSName("comma,and\\backslash".to_owned())]).is_ok(),
            cfg!(any(target_os = "linux", target_os = "android"))
        );
        assert!(
            check_option_values(&[FSName("plain".to_owned()), CUSTOM("plain".to_owned())]).is_ok()
        );
    }

    /// A comma in an option value must not be read as the start of another option by
    /// libfuse or fusermount
    #[test]
    fn option_escaping() {
        use crate::mnt::mount_options::MountOption::*;

        assert_eq!(
            option_to_escaped_string(&FSName("foo,ro".to_owned())),
            "fsname=foo\\,ro"
        );
        assert_eq!(
            option_to_escaped_string(&FSName("back\\slash".to_owned())),
            "fsname=back\\\\slash"
        );
        // A backslash escape must survive libfuse's octal decoding: "\\123" decodes to
        // a literal backslash followed by "123", not to the byte 0o123
        assert_eq!(
            option_to_escaped_string(&FSName("\\123".to_owned())),
            "fsname=\\\\123"
        );
        assert_eq!(
            option_to_escaped_string(&FSName("plain".to_owned())),
            "fsname=plain"
        );
        assert_eq!(
            option_to_escaped_string(&Subtype("plain".to_owned())),
            "subtype=plain"
        );
        assert_eq!(option_to_escaped_string(&RO), "ro");
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
}
