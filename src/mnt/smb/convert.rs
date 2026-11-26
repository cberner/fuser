//! Conversions between what SMB and FUSE call the same things

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::Errno;

/// The Unix epoch as a FILETIME: 100 ns ticks since 1601
const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;

/// `time` as a FILETIME
pub(crate) fn filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => UNIX_EPOCH_AS_FILETIME
            .saturating_add((since.as_nanos() / 100).try_into().unwrap_or(u64::MAX)),
        Err(before) => UNIX_EPOCH_AS_FILETIME.saturating_sub(
            (before.duration().as_nanos() / 100)
                .try_into()
                .unwrap_or(u64::MAX),
        ),
    }
}

/// A FILETIME as a `SystemTime`
pub(crate) fn system_time(filetime: u64) -> SystemTime {
    let ticks_to_duration =
        |ticks: u64| Duration::new(ticks / 10_000_000, (ticks % 10_000_000) as u32 * 100);
    if filetime >= UNIX_EPOCH_AS_FILETIME {
        UNIX_EPOCH + ticks_to_duration(filetime - UNIX_EPOCH_AS_FILETIME)
    } else {
        UNIX_EPOCH - ticks_to_duration(UNIX_EPOCH_AS_FILETIME - filetime)
    }
}

/// Whether `name` matches an SMB search pattern (MS-FSA 2.1.4.4): `*` and `?`, and the DOS
/// forms `<`, `>` and `"`, taken here as `*`, `?` and `.`. Case is ignored, as SMB clients
/// expect.
pub(crate) fn matches(pattern: &str, name: &str) -> bool {
    fn go(pattern: &[char], name: &[char]) -> bool {
        match pattern.split_first() {
            None => name.is_empty(),
            Some(('*' | '<', rest)) => (0..=name.len()).any(|skip| go(rest, &name[skip..])),
            Some(('?' | '>', rest)) => !name.is_empty() && go(rest, &name[1..]),
            Some((&c, rest)) => {
                let c = if c == '"' { '.' } else { c };
                name.first()
                    .is_some_and(|n| n.to_lowercase().eq(c.to_lowercase()))
                    && go(rest, &name[1..])
            }
        }
    }
    if pattern == "*" {
        return true;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    go(&pattern, &name)
}

/// How the share describes an error the filesystem replied with
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    NotFound,
    NotADirectory,
    IsDirectory,
    AccessDenied,
    Exists,
    NotEmpty,
    NotSupported,
    NameInvalid,
    NotSameDevice,
    DiskFull,
    QuotaExceeded,
    InvalidParameter,
    Sharing,
    /// Passed on as the errno itself
    Other,
}

pub(crate) fn error_kind(errno: Errno) -> ErrorKind {
    match errno {
        Errno::ENOENT | Errno::ESTALE => ErrorKind::NotFound,
        Errno::ENOTDIR => ErrorKind::NotADirectory,
        Errno::EISDIR => ErrorKind::IsDirectory,
        Errno::EACCES | Errno::EPERM | Errno::EROFS => ErrorKind::AccessDenied,
        Errno::EEXIST => ErrorKind::Exists,
        Errno::ENOTEMPTY => ErrorKind::NotEmpty,
        Errno::ENOSYS | Errno::ENOTSUP => ErrorKind::NotSupported,
        // The same number as ENOTSUP on Linux, so not a pattern of its own
        errno if errno == Errno::EOPNOTSUPP => ErrorKind::NotSupported,
        Errno::ENAMETOOLONG | Errno::EILSEQ => ErrorKind::NameInvalid,
        Errno::EXDEV => ErrorKind::NotSameDevice,
        Errno::ENOSPC | Errno::EFBIG => ErrorKind::DiskFull,
        Errno::EDQUOT => ErrorKind::QuotaExceeded,
        Errno::EINVAL => ErrorKind::InvalidParameter,
        Errno::EBUSY | Errno::ETXTBSY => ErrorKind::Sharing,
        _ => ErrorKind::Other,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn search_patterns() {
        assert!(matches("*", "hello.txt"));
        assert!(matches("*.txt", "hello.txt"));
        assert!(matches("HELLO.TXT", "hello.txt"));
        assert!(matches("h?llo.*", "hello.txt"));
        assert!(matches("<.txt", "hello.txt"));
        assert!(matches("hello\"txt", "hello.txt"));
        assert!(!matches("*.md", "hello.txt"));
        assert!(!matches("hello", "hello.txt"));
        assert!(!matches("?", ""));
    }

    #[test]
    fn filetimes() {
        assert_eq!(filetime(UNIX_EPOCH), UNIX_EPOCH_AS_FILETIME);
        let time = UNIX_EPOCH + Duration::new(1_700_000_000, 300);
        assert_eq!(
            filetime(time),
            UNIX_EPOCH_AS_FILETIME + 17_000_000_000_000_003
        );
        // 300 ns is a whole number of FILETIME ticks, so nothing is lost
        assert_eq!(system_time(filetime(time)), time);
        let before = UNIX_EPOCH - Duration::from_secs(86_400);
        assert_eq!(system_time(filetime(before)), before);
    }

    #[test]
    fn errors() {
        assert_eq!(error_kind(Errno::ENOENT), ErrorKind::NotFound);
        assert_eq!(error_kind(Errno::ENOTEMPTY), ErrorKind::NotEmpty);
        assert_eq!(error_kind(Errno::EIO), ErrorKind::Other);
    }
}
