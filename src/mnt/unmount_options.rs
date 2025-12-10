use std::{
    collections::HashSet,
    ffi::c_int,
    io::{self, ErrorKind},
};

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum UnmountOption {
    /// Force the unmount
    Force,
    /// Detach the filesystem
    Detach,
    /// Mark the mount as expired
    Expire,
    /// Don't follow symlinks
    NoFollow,
}

fn conflicts_with(option: &UnmountOption) -> Vec<UnmountOption> {
    match option {
        UnmountOption::Force => vec![UnmountOption::Detach, UnmountOption::Expire],
        UnmountOption::Detach => vec![UnmountOption::Force, UnmountOption::Expire],
        UnmountOption::Expire => vec![UnmountOption::Force, UnmountOption::Detach],
        UnmountOption::NoFollow => vec![],
    }
}

pub fn check_option_conflicts(options: &[UnmountOption]) -> Result<(), io::Error> {
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

pub fn to_fusermount_option(option: &UnmountOption) -> Option<String> {
    match option {
        UnmountOption::Force => None,
        UnmountOption::Detach => Some("-z".to_string()),
        UnmountOption::Expire => None,
        UnmountOption::NoFollow => None,
    }
}

pub fn to_unmount_syscall(options: &[UnmountOption]) -> c_int {
    let mut res: c_int = 0;
    for option in options {
        match option {
            UnmountOption::Force => res |= libc::MNT_FORCE,
            UnmountOption::Detach => res |= libc::MNT_DETACH,
            UnmountOption::Expire => res |= libc::MNT_EXPIRE,
            UnmountOption::NoFollow => res |= libc::UMOUNT_NOFOLLOW,
        }
    }
    res
}
