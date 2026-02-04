use crate::Errno;
use bimap::BiHashMap;
use dashmap::{DashMap, mapref::one::Ref};
use lazy_static::lazy_static;
use std::{
    ffi::{CStr, OsStr, OsString},
    os::unix::ffi::OsStrExt,
};

// Sourced from https://github.com/pgdr/moreutils/blob/master/Makefile
const ALL_RAW_ERRNOS: &[libc::c_int] = &[
    libc::EPERM,
    libc::ENOENT,
    libc::ESRCH,
    libc::EINTR,
    libc::EIO,
    libc::ENXIO,
    libc::E2BIG,
    libc::ENOEXEC,
    libc::EBADF,
    libc::ECHILD,
    libc::EAGAIN,
    libc::ENOMEM,
    libc::EACCES,
    libc::EFAULT,
    libc::ENOTBLK,
    libc::EBUSY,
    libc::EEXIST,
    libc::EXDEV,
    libc::ENODEV,
    libc::ENOTDIR,
    libc::EISDIR,
    libc::EINVAL,
    libc::ENFILE,
    libc::EMFILE,
    libc::ENOTTY,
    libc::ETXTBSY,
    libc::EFBIG,
    libc::ENOSPC,
    libc::ESPIPE,
    libc::EROFS,
    libc::EMLINK,
    libc::EPIPE,
    libc::EDOM,
    libc::ERANGE,
    libc::EDEADLK,
    libc::ENAMETOOLONG,
    libc::ENOLCK,
    libc::ENOSYS,
    libc::ENOTEMPTY,
    libc::ELOOP,
    libc::EWOULDBLOCK,
    libc::ENOMSG,
    libc::EIDRM,
    libc::ECHRNG,
    libc::EL2NSYNC,
    libc::EL3HLT,
    libc::EL3RST,
    libc::ELNRNG,
    libc::EUNATCH,
    libc::ENOCSI,
    libc::EL2HLT,
    libc::EBADE,
    libc::EBADR,
    libc::EXFULL,
    libc::ENOANO,
    libc::EBADRQC,
    libc::EBADSLT,
    libc::EDEADLOCK,
    libc::EBFONT,
    libc::ENOSTR,
    libc::ENODATA,
    libc::ETIME,
    libc::ENOSR,
    libc::ENONET,
    libc::ENOPKG,
    libc::EREMOTE,
    libc::ENOLINK,
    libc::EADV,
    libc::ESRMNT,
    libc::ECOMM,
    libc::EPROTO,
    libc::EMULTIHOP,
    libc::EDOTDOT,
    libc::EBADMSG,
    libc::EOVERFLOW,
    libc::ENOTUNIQ,
    libc::EBADFD,
    libc::EREMCHG,
    libc::ELIBACC,
    libc::ELIBBAD,
    libc::ELIBSCN,
    libc::ELIBMAX,
    libc::ELIBEXEC,
    libc::EILSEQ,
    libc::ERESTART,
    libc::ESTRPIPE,
    libc::EUSERS,
    libc::ENOTSOCK,
    libc::EDESTADDRREQ,
    libc::EMSGSIZE,
    libc::EPROTOTYPE,
    libc::ENOPROTOOPT,
    libc::EPROTONOSUPPORT,
    libc::ESOCKTNOSUPPORT,
    libc::EOPNOTSUPP,
    libc::EPFNOSUPPORT,
    libc::EAFNOSUPPORT,
    libc::EADDRINUSE,
    libc::EADDRNOTAVAIL,
    libc::ENETDOWN,
    libc::ENETUNREACH,
    libc::ENETRESET,
    libc::ECONNABORTED,
    libc::ECONNRESET,
    libc::ENOBUFS,
    libc::EISCONN,
    libc::ENOTCONN,
    libc::ESHUTDOWN,
    libc::ETOOMANYREFS,
    libc::ETIMEDOUT,
    libc::ECONNREFUSED,
    libc::EHOSTDOWN,
    libc::EHOSTUNREACH,
    libc::EALREADY,
    libc::EINPROGRESS,
    libc::ESTALE,
    libc::EUCLEAN,
    libc::ENOTNAM,
    libc::ENAVAIL,
    libc::EISNAM,
    libc::EREMOTEIO,
    libc::EDQUOT,
    libc::ENOMEDIUM,
    libc::EMEDIUMTYPE,
    libc::ECANCELED,
    libc::ENOKEY,
    libc::EKEYEXPIRED,
    libc::EKEYREVOKED,
    libc::EKEYREJECTED,
    libc::EOWNERDEAD,
    libc::ENOTRECOVERABLE,
    libc::ERFKILL,
    libc::EHWPOISON,
    libc::ENOTSUP,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Locale(libc::locale_t);

// FIXME: Assumes that locale_t is an opaque string that is immutable and
// has static lifetime, and locales in one language are immutable
unsafe impl Send for Locale {}
unsafe impl Sync for Locale {}

lazy_static! {
    static ref ERRNO_MAPPING: ErrnoMapping = ErrnoMapping::new();
}

type ErrnoLocaleMapping = BiHashMap<Errno, OsString>;
type ErrnoMapping = DashMap<Locale, ErrnoLocaleMapping>;

unsafe extern "C" {
    fn strerror_l(errnum: i32, locale: libc::locale_t) -> *const libc::c_char;
}

fn get_current_message_locale() -> Locale {
    let locale = unsafe { libc::uselocale(std::ptr::null_mut()) };
    Locale(locale)
}

fn populate_errno_mapping(mapping: &mut ErrnoLocaleMapping, locale: Locale) {
    for errno in ALL_RAW_ERRNOS.iter() {
        let errno = Errno::from_i32(*errno);
        if mapping.contains_left(&errno) {
            continue;
        }
        let error_str = unsafe { strerror_l(errno.code(), locale.0) };
        mapping.insert(errno, unsafe {
            OsStr::from_bytes(CStr::from_ptr(error_str).to_bytes()).to_os_string()
        });
    }
}

fn get_errno_mapping(
    mapping: &ErrnoMapping,
    locale: Locale,
) -> Ref<'_, Locale, ErrnoLocaleMapping> {
    match mapping.get(&locale) {
        Some(locale_mapping) => return locale_mapping,
        None => (),
    };
    let ref_mut = mapping.entry(locale).or_insert_with(|| {
        let mut mapping = ErrnoLocaleMapping::new();
        populate_errno_mapping(&mut mapping, locale);
        mapping
    });
    ref_mut.downgrade()
}

#[allow(unused)]
pub(crate) fn get_errno_message(errno: impl Into<Errno>) -> Option<OsString> {
    let locale = get_current_message_locale();
    let mapping = get_errno_mapping(&ERRNO_MAPPING, locale);
    mapping
        .get_by_left(&errno.into())
        .map(|os_str| os_str.to_owned())
}

/// Attempts to convert a message to an errno object.
pub(crate) fn get_errno_by_message(message: impl Into<OsString>) -> Option<Errno> {
    let locale = get_current_message_locale();
    let mapping = get_errno_mapping(&ERRNO_MAPPING, locale);
    mapping.get_by_right(&message.into()).map(|errno| *errno)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_errno_message() {
        let errno = Errno::EPERM;
        let message = get_errno_message(errno).expect("message should be present");
        assert_eq!(message, "Operation not permitted");
    }

    #[test]
    fn test_get_errno_by_message() {
        let message = OsString::from("Operation not permitted");
        let errno = get_errno_by_message(message).expect("errno should be present");
        assert_eq!(errno, Errno::EPERM);
    }
}
