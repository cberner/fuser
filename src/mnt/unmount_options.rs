use std::{
    collections::HashSet,
    ffi::c_int,
    io::{self, ErrorKind},
};

/// Unmount options accepted by the umount2 or unmount syscall
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum UnmountOption {
    /// Force the unmount
    Force,
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    /// Detach the filesystem
    Detach,
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    /// Mark the mount as expired
    Expire,
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    /// Don't follow symlinks
    NoFollow,
}

fn conflicts_with(option: &UnmountOption) -> Vec<UnmountOption> {
    match option {
        UnmountOption::Force => vec![
            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            UnmountOption::Detach,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            UnmountOption::Expire,
        ],
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        UnmountOption::Detach => vec![UnmountOption::Force, UnmountOption::Expire],
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        UnmountOption::Expire => vec![UnmountOption::Force, UnmountOption::Detach],
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        UnmountOption::NoFollow => vec![],
    }
}

pub(crate) fn check_option_conflicts(options: &[UnmountOption]) -> Result<(), io::Error> {
    let mut options_set = HashSet::new();
    options_set.extend(options.iter().cloned());
    let conflicting: HashSet<UnmountOption> = options.iter().flat_map(conflicts_with).collect();
    let intersection: Vec<UnmountOption> =
        conflicting.intersection(&options_set).cloned().collect();
    if intersection.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Conflicting unmount options found: {intersection:?}"),
        ))
    }
}

pub(crate) fn to_fusermount_option(option: &UnmountOption) -> Option<String> {
    match option {
        UnmountOption::Force => None,
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        UnmountOption::Detach => Some("-z".to_string()),
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        UnmountOption::Expire => None,
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        UnmountOption::NoFollow => None,
    }
}

pub(crate) fn to_unmount_syscall(options: &[UnmountOption]) -> c_int {
    let mut res: c_int = 0;
    for option in options {
        match option {
            UnmountOption::Force => res |= libc::MNT_FORCE,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            UnmountOption::Detach => res |= libc::MNT_DETACH,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            UnmountOption::Expire => res |= libc::MNT_EXPIRE,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            UnmountOption::NoFollow => res |= libc::UMOUNT_NOFOLLOW,
        }
    }
    res
}
