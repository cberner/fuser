use std::io;
use std::io::ErrorKind;
use std::{collections::HashSet, ffi::OsStr};

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
    /// Allow all users to access files on this filesystem. By default access is restricted to the
    /// user who mounted it
    AllowOther,
    /// Allow the root user to access this filesystem, in addition to the user who mounted it
    AllowRoot,
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

impl<'a> From<&'a str> for MountOption {
    fn from(s: &'a str) -> MountOption {
        match s {
            "auto_unmount" => MountOption::AutoUnmount,
            "allow_other" => MountOption::AllowOther,
            "allow_root" => MountOption::AllowRoot,
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

pub fn check_option_conflicts(options: &[MountOption]) -> Result<(), io::Error> {
    let mut options_set = HashSet::new();
    options_set.extend(options.iter().cloned());
    let conflicting: HashSet<MountOption> = options.iter().map(conflicts_with).flatten().collect();
    let intersection: Vec<MountOption> = conflicting.intersection(&options_set).cloned().collect();
    if !intersection.is_empty() {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Conflicting mount options found: {:?}", intersection),
        ))
    } else {
        Ok(())
    }
}

fn conflicts_with(option: &MountOption) -> Vec<MountOption> {
    match option {
        MountOption::FSName(_) => vec![],
        MountOption::Subtype(_) => vec![],
        MountOption::CUSTOM(_) => vec![],
        MountOption::AllowOther => vec![MountOption::AllowRoot],
        MountOption::AllowRoot => vec![MountOption::AllowOther],
        MountOption::AutoUnmount => vec![],
        MountOption::DefaultPermissions => vec![],
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
        MountOption::DirSync => vec![],
        MountOption::Sync => vec![MountOption::Async],
        MountOption::Async => vec![MountOption::Sync],
    }
}

impl std::fmt::Display for MountOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountOption::FSName(name) => f.write_fmt(format_args!("fsname={}", name)),
            MountOption::Subtype(subtype) => f.write_fmt(format_args!("subtype={}", subtype)),
            MountOption::CUSTOM(value) => f.write_str(value),
            MountOption::AutoUnmount => f.write_str("auto_unmount"),
            MountOption::AllowOther => f.write_str("allow_other"),
            // AllowRoot is implemented by allowing everyone access and then restricting to
            // root + owner within fuser
            MountOption::AllowRoot => f.write_str("allow_other"),
            MountOption::DefaultPermissions => f.write_str("default_permissions"),
            MountOption::Dev => f.write_str("dev"),
            MountOption::NoDev => f.write_str("nodev"),
            MountOption::Suid => f.write_str("suid"),
            MountOption::NoSuid => f.write_str("nosuid"),
            MountOption::RO => f.write_str("ro"),
            MountOption::RW => f.write_str("rw"),
            MountOption::Exec => f.write_str("exec"),
            MountOption::NoExec => f.write_str("noexec"),
            MountOption::Atime => f.write_str("atime"),
            MountOption::NoAtime => f.write_str("noatime"),
            MountOption::DirSync => f.write_str("dirsync"),
            MountOption::Sync => f.write_str("sync"),
            MountOption::Async => f.write_str("async"),
        }
    }
}

// Format option to be passed to libfuse or kernel
pub fn option_to_string(option: &MountOption) -> String {
    option.to_string()
}

/// Parses mount command args.
///
/// Input: ["-o", "suid", "-o", "ro,nodev,noexec", "-osync"]
/// Output Ok([Suid, RO, NoDev, NoExec, Sync])
pub(crate) fn parse_options_from_args(args: &[&OsStr]) -> io::Result<Vec<MountOption>> {
    let err = |x| io::Error::new(ErrorKind::InvalidInput, x);
    let args: Option<Vec<_>> = args.iter().map(|x| x.to_str()).collect();
    let args = args.ok_or_else(|| err("Error parsing args: Invalid UTF-8".to_owned()))?;
    let mut it = args.iter();
    let mut out = vec![];
    loop {
        let opt = match it.next() {
            None => break,
            Some(&"-o") => *it.next().ok_or_else(|| {
                err("Error parsing args: Expected option, reached end of args".to_owned())
            })?,
            Some(x) if x.starts_with("-o") => &x[2..],
            Some(x) => return Err(err(format!("Error parsing args: expected -o, got {}", x))),
        };
        for x in opt.split(',') {
            out.push(MountOption::from(x))
        }
    }
    Ok(out)
}

#[cfg(test)]
mod test {
    use std::os::unix::prelude::OsStrExt;

    use super::*;

    #[test]
    fn option_checking() {
        assert!(check_option_conflicts(&[MountOption::Suid, MountOption::NoSuid]).is_err());
        assert!(check_option_conflicts(&[MountOption::Suid, MountOption::NoExec]).is_ok());
    }
    #[test]
    fn option_round_trip() {
        use super::MountOption::*;
        for x in [
            FSName("Blah".to_owned()),
            Subtype("Bloo".to_owned()),
            CUSTOM("bongos".to_owned()),
            AllowOther,
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
        ]
        .iter()
        {
            assert_eq!(*x, MountOption::from(option_to_string(x).as_ref()))
        }
    }

    #[test]
    fn test_parse_options() {
        use super::MountOption::*;

        assert_eq!(parse_options_from_args(&[]).unwrap(), &[]);

        let o: Vec<_> = "-o suid -o ro,nodev,noexec -osync"
            .split(' ')
            .map(OsStr::new)
            .collect();
        let out = parse_options_from_args(o.as_ref()).unwrap();
        assert_eq!(out, [Suid, RO, NoDev, NoExec, Sync]);

        assert!(parse_options_from_args(&[OsStr::new("-o")]).is_err());
        assert!(parse_options_from_args(&[OsStr::new("not o")]).is_err());
        assert!(parse_options_from_args(&[OsStr::from_bytes(b"-o\xc3\x28")]).is_err());
    }
}
