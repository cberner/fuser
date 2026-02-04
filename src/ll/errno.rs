use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::NulError;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use bimap::BiHashMap;
use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use lazy_static::lazy_static;

use crate::Errno;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LocaleId(CString);

impl TryFrom<&str> for LocaleId {
    type Error = NulError;
    fn try_from(locale: &str) -> Result<Self, Self::Error> {
        let cstr = CString::new(locale)?;
        Ok(Self(cstr))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Locale(libc::locale_t);

impl Locale {
    fn new(category: libc::c_int, locale: LocaleId) -> Result<Self, std::io::Error> {
        let inner = unsafe { libc::newlocale(category, locale.0.as_ptr(), std::ptr::null_mut()) };
        if inner.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(inner))
    }
}

impl Drop for Locale {
    fn drop(&mut self) {
        unsafe { libc::freelocale(self.0) };
    }
}

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
    #[cfg(target_os = "linux")]
    libc::ECHRNG,
    #[cfg(target_os = "linux")]
    libc::EL2NSYNC,
    #[cfg(target_os = "linux")]
    libc::EL3HLT,
    #[cfg(target_os = "linux")]
    libc::EL3RST,
    #[cfg(target_os = "linux")]
    libc::ELNRNG,
    #[cfg(target_os = "linux")]
    libc::EUNATCH,
    #[cfg(target_os = "linux")]
    libc::ENOCSI,
    #[cfg(target_os = "linux")]
    libc::EL2HLT,
    #[cfg(target_os = "linux")]
    libc::EBADE,
    #[cfg(target_os = "linux")]
    libc::EBADR,
    #[cfg(target_os = "linux")]
    libc::EXFULL,
    #[cfg(target_os = "linux")]
    libc::ENOANO,
    #[cfg(target_os = "linux")]
    libc::EBADRQC,
    #[cfg(target_os = "linux")]
    libc::EBADSLT,
    #[cfg(target_os = "linux")]
    libc::EDEADLOCK,
    #[cfg(target_os = "linux")]
    libc::EBFONT,
    libc::ENOSTR,
    libc::ENODATA,
    libc::ETIME,
    libc::ENOSR,
    #[cfg(target_os = "linux")]
    libc::ENONET,
    #[cfg(target_os = "linux")]
    libc::ENOPKG,
    libc::EREMOTE,
    libc::ENOLINK,
    #[cfg(target_os = "linux")]
    libc::EADV,
    #[cfg(target_os = "linux")]
    libc::ESRMNT,
    #[cfg(target_os = "linux")]
    libc::ECOMM,
    libc::EPROTO,
    libc::EMULTIHOP,
    #[cfg(target_os = "linux")]
    libc::EDOTDOT,
    libc::EBADMSG,
    libc::EOVERFLOW,
    #[cfg(target_os = "linux")]
    libc::ENOTUNIQ,
    #[cfg(target_os = "linux")]
    libc::EBADFD,
    #[cfg(target_os = "linux")]
    libc::EREMCHG,
    #[cfg(target_os = "linux")]
    libc::ELIBACC,
    #[cfg(target_os = "linux")]
    libc::ELIBBAD,
    #[cfg(target_os = "linux")]
    libc::ELIBSCN,
    #[cfg(target_os = "linux")]
    libc::ELIBMAX,
    #[cfg(target_os = "linux")]
    libc::ELIBEXEC,
    libc::EILSEQ,
    #[cfg(target_os = "linux")]
    libc::ERESTART,
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    libc::EUCLEAN,
    #[cfg(target_os = "linux")]
    libc::ENOTNAM,
    #[cfg(target_os = "linux")]
    libc::ENAVAIL,
    #[cfg(target_os = "linux")]
    libc::EISNAM,
    #[cfg(target_os = "linux")]
    libc::EREMOTEIO,
    libc::EDQUOT,
    #[cfg(target_os = "linux")]
    libc::ENOMEDIUM,
    #[cfg(target_os = "linux")]
    libc::EMEDIUMTYPE,
    libc::ECANCELED,
    #[cfg(target_os = "linux")]
    libc::ENOKEY,
    #[cfg(target_os = "linux")]
    libc::EKEYEXPIRED,
    #[cfg(target_os = "linux")]
    libc::EKEYREVOKED,
    #[cfg(target_os = "linux")]
    libc::EKEYREJECTED,
    libc::EOWNERDEAD,
    libc::ENOTRECOVERABLE,
    #[cfg(target_os = "linux")]
    libc::ERFKILL,
    #[cfg(target_os = "linux")]
    libc::EHWPOISON,
    libc::ENOTSUP,
];

lazy_static! {
    static ref ERRNO_MAPPING: ErrnoMapping = ErrnoMapping::new();
}

type ErrnoLocaleMapping = BiHashMap<Errno, OsString>;
type ErrnoMapping = DashMap<LocaleId, ErrnoLocaleMapping>;

unsafe extern "C" {
    fn strerror_l(errnum: i32, locale: libc::locale_t) -> *const libc::c_char;
}

fn populate_errno_mapping(
    mapping: &mut ErrnoLocaleMapping,
    locale_id: &LocaleId,
) -> Result<(), std::io::Error> {
    let locale = Locale::new(libc::LC_MESSAGES, locale_id.clone())?;
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
    Ok(())
}

fn get_errno_mapping<'a>(
    mapping: &'a ErrnoMapping,
    locale_id: &LocaleId,
) -> Result<Ref<'a, LocaleId, ErrnoLocaleMapping>, std::io::Error> {
    if let Some(locale_mapping) = mapping.get(locale_id) {
        return Ok(locale_mapping);
    }
    let ref_mut =
        mapping
            .entry(locale_id.clone())
            .or_try_insert_with(|| -> Result<_, std::io::Error> {
                let mut mapping = ErrnoLocaleMapping::new();
                populate_errno_mapping(&mut mapping, locale_id)?;
                Ok(mapping)
            })?;
    Ok(ref_mut.downgrade())
}

#[allow(unused)]
pub(crate) fn get_errno_message(
    errno: impl Into<Errno>,
    locale_id: &LocaleId,
) -> Result<Option<OsString>, std::io::Error> {
    let mapping = get_errno_mapping(&ERRNO_MAPPING, locale_id)?;
    Ok(mapping
        .get_by_left(&errno.into())
        .map(|os_str| os_str.to_owned()))
}

/// Attempts to convert a message to an errno object.
#[allow(unused)]
pub(crate) fn get_errno_by_message(
    message: impl Into<OsString>,
    locale_id: &LocaleId,
) -> Result<Option<Errno>, std::io::Error> {
    let mapping = get_errno_mapping(&ERRNO_MAPPING, locale_id)?;
    Ok(mapping.get_by_right(&message.into()).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_errno_message() {
        let errno = Errno::EPERM;
        let message = get_errno_message(errno, &"C".try_into().expect("locale should be valid"))
            .expect("locale should be valid")
            .expect("message should be present");
        assert_eq!(message, "Operation not permitted");
    }

    #[test]
    fn test_get_errno_by_message() {
        let message = OsString::from("Operation not permitted");
        let errno = get_errno_by_message(message, &"C".try_into().expect("locale should be valid"))
            .expect("locale should be valid")
            .expect("errno should be present");
        assert_eq!(errno, Errno::EPERM);
    }
}
