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

impl Clone for Request {
    fn clone(&self) -> Self {
        Request {
            header: fuse_in_header {
                len: self.header.len,
                opcode: self.header.opcode,
                unique: self.header.unique,
                nodeid: self.header.nodeid,
                uid: self.header.uid,
                gid: self.header.gid,
                pid: self.header.pid,
                padding: self.header.padding,
            },
        }
    }
}

impl Request {
    #[ref_cast_custom]
    pub(crate) fn ref_cast(header: &fuse_in_header) -> &Request;

    /// Returns the unique identifier of this request
    #[inline]
    pub fn unique(&self) -> ll::RequestId {
        ll::RequestId(self.header.unique)
    }

    /// Returns the uid of this request
    #[inline]
    pub fn uid(&self) -> u32 {
        self.header.uid
    }

    /// Returns the gid of this request
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
