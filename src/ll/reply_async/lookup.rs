//! Response data implementation of [`crate::AsyncFilesystem::lookup`] operation to
//! send to the kernel

#![allow(missing_docs, missing_debug_implementations)]

use std::time::Duration;

use crate::FileAttr;
use crate::Generation;
use crate::ll::ResponseStruct;
use crate::ll::ioslice_concat::IosliceConcat;
use crate::ll::reply::Attr;
use crate::ll::reply::Response;

/// Response data from [`crate::AsyncFilesystem::lookup`] operation
#[derive(Debug)]
pub struct LookupResponse {
    ttl: Duration,
    attr: FileAttr,
    generation: Generation,
}

impl LookupResponse {
    /// `ttl` is the time for which this response may be cached
    /// `attr` is the attributes of the file
    /// `generation`
    pub fn new(ttl: Duration, attr: FileAttr, generation: Generation) -> Self {
        Self {
            ttl,
            attr,
            generation,
        }
    }
}

impl Response for LookupResponse {
    fn payload(&self) -> impl IosliceConcat {
        ResponseStruct::new_entry(
            self.attr.ino,
            self.generation,
            &Attr::from(self.attr),
            self.ttl,
            self.ttl,
        )
    }
}
