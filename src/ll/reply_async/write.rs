//! Response data implementation of [`crate::AsyncFilesystem::write`] operation to
//! send to the kernel

use crate::ll::ResponseStruct;
use crate::ll::ioslice_concat::IosliceConcat;
use crate::ll::reply::Response;

/// Response data from [`crate::AsyncFilesystem::write`] operation
#[derive(Debug)]
pub struct WriteResponse {
    size: u32,
}

impl WriteResponse {
    /// Creates a `WriteResponse` object
    pub fn new(size: u32) -> Self {
        Self { size }
    }
}

impl Response for WriteResponse {
    fn payload(&self) -> impl IosliceConcat {
        ResponseStruct::new_write(self.size)
    }
}
