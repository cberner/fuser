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
