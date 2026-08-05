use ref_cast::RefCastCustom;
use ref_cast::ref_cast_custom;

use crate::ll;
use crate::ll::fuse_abi::fuse_in_header;

/// FUSE request parameters.
#[derive(Debug, RefCastCustom)]
#[repr(transparent)]
pub struct Request {
    header: fuse_in_header,
}

impl Request {
    #[ref_cast_custom]
    pub(crate) fn ref_cast(header: &fuse_in_header) -> &Request;

    /// Returns the unique identifier of this request
    #[inline]
    pub fn unique(&self) -> ll::RequestId {
        ll::RequestId(self.header.unique)
    }

    /// Returns the uid of this request, or [`crate::FUSE_INVALID_UIDGID`] when the kernel
    /// withheld it.
    ///
    /// It withholds it on every request that does not create an inode, and only once
    /// [`crate::InitFlags::FUSE_ALLOW_IDMAP`] has been negotiated - which a filesystem has to
    /// ask for, so one that does not is never handed an invalid id. The requests that do
    /// create an inode still carry ids, and they are the owner the new inode should get,
    /// already mapped.
    #[inline]
    pub fn uid(&self) -> u32 {
        self.header.uid
    }

    /// Returns the gid of this request, or [`crate::FUSE_INVALID_UIDGID`] when the kernel
    /// withheld it. See [`Request::uid`] for when that is.
    #[inline]
    pub fn gid(&self) -> u32 {
        self.header.gid
    }

    /// Returns the pid of this request
    #[inline]
    pub fn pid(&self) -> u32 {
        self.header.pid
    }
}
