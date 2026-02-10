use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::NulError;
use std::ffi::OsStr;
use std::ffi::OsString;
#[cfg(not(any(target_os = "dragonfly", target_os = "vxworks", target_os = "rtems")))]
use std::ffi::c_int;
use std::io;
use std::os::unix::ffi::OsStrExt;

use bimap::BiHashMap;
use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use lazy_static::lazy_static;
use libc::strerror_r;

use crate::Errno;
unsafe extern "C" {
    #[cfg(not(any(target_os = "dragonfly", target_os = "vxworks", target_os = "rtems")))]
    #[cfg_attr(
        any(
            target_os = "linux",
            target_os = "emscripten",
            target_os = "fuchsia",
            target_os = "l4re",
            target_os = "hurd",
        ),
        link_name = "__errno_location"
    )]
    #[cfg_attr(
        any(
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "android",
            target_os = "redox",
            target_os = "nuttx",
            target_env = "newlib"
        ),
        link_name = "__errno"
    )]
    #[cfg_attr(
        any(target_os = "solaris", target_os = "illumos"),
        link_name = "___errno"
    )]
    #[cfg_attr(target_os = "nto", link_name = "__get_errno_ptr")]
    #[cfg_attr(
        any(target_os = "freebsd", target_vendor = "apple"),
        link_name = "__error"
    )]
    #[cfg_attr(target_os = "haiku", link_name = "_errnop")]
    #[cfg_attr(target_os = "aix", link_name = "_Errno")]
    fn errno_location() -> *mut c_int;
}

pub(crate) fn set_errno(value: i32) {
    unsafe { *errno_location() = value };
}

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

unsafe impl Send for Locale {}
unsafe impl Sync for Locale {}

impl Locale {
    fn new(category: libc::c_int, locale: LocaleId) -> Result<Self, std::io::Error> {
        let inner = unsafe { libc::newlocale(category, locale.0.as_ptr(), std::ptr::null_mut()) };
        if inner.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(inner))
    }

    /// Sets the locale for the current thread.
    /// SAFETY: this function stores a raw pointer to the previous locale, which may be
    /// invalid when another Locale object is dropped. The locale guards must be dropped
    /// in the correct initialization order.
    unsafe fn activate(&self) -> LocaleActivationGuard<'_> {
        let old_locale = unsafe { libc::uselocale(self.0) };
        LocaleActivationGuard::new(self, old_locale)
    }
}

impl Drop for Locale {
    fn drop(&mut self) {
        unsafe { libc::freelocale(self.0) };
    }
}

struct LocaleActivationGuard<'a> {
    _locale: &'a Locale,
    old_locale: libc::locale_t,
}

impl<'a> LocaleActivationGuard<'a> {
    fn new(locale: &'a Locale, old_locale: libc::locale_t) -> Self {
        Self {
            _locale: locale,
            old_locale,
        }
    }
}

impl Drop for LocaleActivationGuard<'_> {
    fn drop(&mut self) {
        unsafe { libc::uselocale(self.old_locale) };
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
    #[cfg(not(target_os = "macos"))]
    libc::ECHRNG,
    #[cfg(not(target_os = "macos"))]
    libc::EL2NSYNC,
    #[cfg(not(target_os = "macos"))]
    libc::EL3HLT,
    #[cfg(not(target_os = "macos"))]
    libc::EL3RST,
    #[cfg(not(target_os = "macos"))]
    libc::ELNRNG,
    #[cfg(not(target_os = "macos"))]
    libc::EUNATCH,
    #[cfg(not(target_os = "macos"))]
    libc::ENOCSI,
    #[cfg(not(target_os = "macos"))]
    libc::EL2HLT,
    #[cfg(not(target_os = "macos"))]
    libc::EBADE,
    #[cfg(not(target_os = "macos"))]
    libc::EBADR,
    #[cfg(not(target_os = "macos"))]
    libc::EXFULL,
    #[cfg(not(target_os = "macos"))]
    libc::ENOANO,
    #[cfg(not(target_os = "macos"))]
    libc::EBADRQC,
    #[cfg(not(target_os = "macos"))]
    libc::EBADSLT,
    #[cfg(not(target_os = "macos"))]
    libc::EDEADLOCK,
    #[cfg(not(target_os = "macos"))]
    libc::EBFONT,
    libc::ENOSTR,
    libc::ENODATA,
    libc::ETIME,
    libc::ENOSR,
    #[cfg(not(target_os = "macos"))]
    libc::ENONET,
    #[cfg(not(target_os = "macos"))]
    libc::ENOPKG,
    libc::EREMOTE,
    libc::ENOLINK,
    #[cfg(not(target_os = "macos"))]
    libc::EADV,
    #[cfg(not(target_os = "macos"))]
    libc::ESRMNT,
    #[cfg(not(target_os = "macos"))]
    libc::ECOMM,
    libc::EPROTO,
    libc::EMULTIHOP,
    #[cfg(not(target_os = "macos"))]
    libc::EDOTDOT,
    libc::EBADMSG,
    libc::EOVERFLOW,
    #[cfg(not(target_os = "macos"))]
    libc::ENOTUNIQ,
    #[cfg(not(target_os = "macos"))]
    libc::EBADFD,
    #[cfg(not(target_os = "macos"))]
    libc::EREMCHG,
    #[cfg(not(target_os = "macos"))]
    libc::ELIBACC,
    #[cfg(not(target_os = "macos"))]
    libc::ELIBBAD,
    #[cfg(not(target_os = "macos"))]
    libc::ELIBSCN,
    #[cfg(not(target_os = "macos"))]
    libc::ELIBMAX,
    #[cfg(not(target_os = "macos"))]
    libc::ELIBEXEC,
    libc::EILSEQ,
    #[cfg(not(target_os = "macos"))]
    libc::ERESTART,
    #[cfg(not(target_os = "macos"))]
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
    #[cfg(not(target_os = "macos"))]
    libc::EUCLEAN,
    #[cfg(not(target_os = "macos"))]
    libc::ENOTNAM,
    #[cfg(not(target_os = "macos"))]
    libc::ENAVAIL,
    #[cfg(not(target_os = "macos"))]
    libc::EISNAM,
    #[cfg(not(target_os = "macos"))]
    libc::EREMOTEIO,
    libc::EDQUOT,
    #[cfg(not(target_os = "macos"))]
    libc::ENOMEDIUM,
    #[cfg(not(target_os = "macos"))]
    libc::EMEDIUMTYPE,
    libc::ECANCELED,
    #[cfg(not(target_os = "macos"))]
    libc::ENOKEY,
    #[cfg(not(target_os = "macos"))]
    libc::EKEYEXPIRED,
    #[cfg(not(target_os = "macos"))]
    libc::EKEYREVOKED,
    #[cfg(not(target_os = "macos"))]
    libc::EKEYREJECTED,
    libc::EOWNERDEAD,
    libc::ENOTRECOVERABLE,
    #[cfg(not(target_os = "macos"))]
    libc::ERFKILL,
    #[cfg(not(target_os = "macos"))]
    libc::EHWPOISON,
    libc::ENOTSUP,
];

lazy_static! {
    static ref ERRNO_MAPPING: ErrnoMapping = ErrnoMapping::new();
}

type ErrnoLocaleMapping = BiHashMap<Errno, OsString>;
type ErrnoMapping = DashMap<LocaleId, ErrnoLocaleMapping>;

fn strerror_r_dynamic(errnum: i32) -> Result<OsString, io::Error> {
    let mut buffer = vec![0i8; 1024];
    set_errno(0);
    while unsafe { strerror_r(errnum, buffer.as_mut_ptr(), buffer.len()) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error().unwrap_or(0) == libc::ERANGE {
            buffer.resize(buffer.len() + 1024, 0);
            continue;
        } else {
            return Err(error);
        }
    }
    let cstr = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    Ok(OsStr::from_bytes(cstr.to_bytes()).to_os_string())
}

fn populate_errno_mapping(
    mapping: &mut ErrnoLocaleMapping,
    locale_id: &LocaleId,
) -> Result<(), std::io::Error> {
    let locale = Locale::new(libc::LC_MESSAGES, locale_id.clone())?;
    let _locale_guard = unsafe { locale.activate() };
    for errno in ALL_RAW_ERRNOS.iter() {
        let errno = Errno::from_i32(*errno);
        if mapping.contains_left(&errno) {
            continue;
        }
        let error_str = match strerror_r_dynamic(errno.code()) {
            Ok(os_str) => os_str,
            Err(_) => continue,
        };
        mapping.insert(errno, error_str);
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
