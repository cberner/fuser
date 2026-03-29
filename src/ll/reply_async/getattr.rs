//! Response data implementation of [`crate::AsyncFilesystem::getattr`] operation to
//! send to the kernel

use std::time::Duration;

use crate::FileAttr;
use crate::ll::ResponseStruct;
use crate::ll::ioslice_concat::IosliceConcat;
use crate::ll::reply::Attr;
use crate::ll::reply::Response;

/// Response data from [`crate::AsyncFilesystem::getattr`] operation
#[derive(Debug)]
pub struct GetAttrResponse {
    ttl: Duration,
    attr: FileAttr,
}

impl GetAttrResponse {
    /// Creates a `GetAttrResponse` object
    pub fn new(ttl: Duration, attr: FileAttr) -> Self {
        Self { ttl, attr }
    }
}

impl Response for GetAttrResponse {
    fn payload(&self) -> impl IosliceConcat {
        ResponseStruct::new_attr(&self.ttl, &Attr::from(self.attr))
    }
}
