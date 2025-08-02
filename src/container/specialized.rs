use super::core::{Container, Borrow, BorrowError};
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::str::Utf8Error;
use std::string::FromUtf8Error;

// --- u8 & string specializations ---

#[derive(Debug, PartialEq)]
pub enum ToStringError {
    Utf8(Utf8Error),
    FromUtf8(FromUtf8Error),
    Lock(BorrowError),
}

impl From<Utf8Error> for ToStringError {
    fn from(err: Utf8Error) -> Self {
        ToStringError::Utf8(err)
    }
}

impl From<FromUtf8Error> for ToStringError {
    fn from(err: FromUtf8Error) -> Self {
        ToStringError::FromUtf8(err)
    }
}

impl From<BorrowError> for ToStringError {
    fn from(err: BorrowError) -> Self {
        ToStringError::Lock(err)
    }
}

// TODO: Consider implementing std::error::Error for ToStringError
// impl std::error::Error for ToStringError { ... }

// --- From String and OsString implementations for Container<'a, u8> ---

impl From<String> for Container<'_, u8> {
    fn from(s: String) -> Self {
        Container::Vec(s.into_bytes())
    }
}

impl<'a> From<&'a str> for Container<'a, u8> {
    fn from(s: &'a str) -> Self {
        Container::Ref(s.as_bytes())
    }
}

impl From<OsString> for Container<'_, u8> {
    fn from(s: OsString) -> Self {
        Container::Vec(s.into_vec())
    }
}

impl<'a> From<&'a OsStr> for Container<'a, u8> {
    fn from(s: &'a OsStr) -> Self {
        Container::Ref(s.as_bytes())
    }
}

// --- String and OsString methods for Container<'a, u8> ---

impl Container<'_, u8> {
    /// Converts the bytes to an owned UTF-8 String.
    /// Most likely, this is a copy.
    /// # Errors
    /// Returns an error if the byte slice is not valid UTF-8.
    /// Returns an error if the source data is not available.
    pub fn try_to_string(&self) -> Result<String, ToStringError> {
        let borrowed = self.try_borrow()?;
        Ok(std::str::from_utf8(&borrowed)?.to_string())
    }

    /// Converts the container's content to an owned `OsString`.
    /// Most likely, this is a copy.
    /// # Errors
    /// Returns an error if the source data is not available.
    pub fn try_to_os_string(&self) -> Result<OsString, ToStringError> {
        let borrowed = self.try_borrow()?;
        Ok(OsStr::from_bytes(&borrowed).to_os_string())
    }
}

// --- String and OsString methods for Borrow<'a, u8> ---

impl Borrow<'_, u8> {
    /// Converts the borrowed bytes to an borrowed UTF-8 String.
    /// # Errors
    /// Returns an error if the byte slice is not valid UTF-8.
    pub fn try_to_str(&self) -> Result<&str, ToStringError> {
        Ok(std::str::from_utf8(self)?)
    }

    /// Converts the borrowed bytes to a borrowed `OsStr`.
    #[must_use]    
    pub fn to_os_str(&self) -> &OsStr {
        OsStr::from_bytes(self)
    }
}