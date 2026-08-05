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

    /// Returns the uid of the process that triggered this request, or `None` when the kernel
    /// did not send one.
    ///
    /// An idmapped mount has none to send: which ids a caller would have depends on the mount
    /// it came through. Nothing is left needing them. The capability that allows such a mount,
    /// [`crate::InitFlags::FUSE_ALLOW_IDMAP`], can only be negotiated where
    /// `default_permissions` is in force, so the kernel makes the access checks these ids
    /// would otherwise serve, and the requests that create an inode are given an
    /// [`crate::Owner`] naming who it belongs to. Those ids reach the filesystem only that
    /// way: they are the owner mapped through the mount rather than the caller's, so
    /// reporting them here would invite a check against the wrong identity.
    ///
    /// A filesystem that does not request that capability is always given ids.
    #[inline]
    pub fn uid(&self) -> Option<u32> {
        (self.header.uid != crate::FUSE_INVALID_UIDGID).then_some(self.header.uid)
    }

    /// Returns the gid of the process that triggered this request, or `None` when the kernel
    /// did not send one. See [`Request::uid`] for when that is.
    #[inline]
    pub fn gid(&self) -> Option<u32> {
        (self.header.gid != crate::FUSE_INVALID_UIDGID).then_some(self.header.gid)
    }

    /// Returns the pid of this request
    #[inline]
    pub fn pid(&self) -> u32 {
        self.header.pid
    }
}
