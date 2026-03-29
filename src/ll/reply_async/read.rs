//! Response data implementation of [`crate::AsyncFilesystem::read`] operation to
//! send to the kernel

use std::io::IoSlice;
use std::sync::Arc;

use crate::ll::{ioslice_concat::IosliceConcat, reply::Response};

/// Internal representation of the response data, which
/// can be either owned or shared.
#[derive(Debug)]
enum ReadResponseData {
    Owned(Vec<u8>),
    Shared {
        data: Arc<[u8]>,
        start: usize,
        end: usize,
    },
}

/// Response data from [`crate::AsyncFilesystem::read`] operation
#[derive(Debug)]
pub struct ReadResponse {
    data: ReadResponseData,
}

impl ReadResponse {
    /// Creates a new [`ReadResponse`] with a specified buffer.
    pub fn new(data: Vec<u8>) -> ReadResponse {
        ReadResponse {
            data: ReadResponseData::Owned(data),
        }
    }

    /// Creates a [`ReadResponse`] backed by a slice of shared data without copying it.
    ///
    /// The requested range is clamped to the bounds of `data`.
    pub fn from_shared_slice(data: Arc<[u8]>, offset: usize, size: usize) -> ReadResponse {
        let start = offset.min(data.len());
        let end = start.saturating_add(size).min(data.len());
        ReadResponse {
            data: ReadResponseData::Shared { data, start, end },
        }
    }

    fn bytes(&self) -> &[u8] {
        match &self.data {
            ReadResponseData::Owned(data) => data.as_slice(),
            ReadResponseData::Shared { data, start, end } => &data[*start..*end],
        }
    }
}

impl Response for ReadResponse {
    fn payload(&self) -> impl IosliceConcat {
        [IoSlice::new(self.bytes())]
    }
}

#[cfg(test)]
mod tests {
    use super::ReadResponse;
    use std::sync::Arc;

    #[test]
    fn shared_slice_clamps_to_bounds() {
        let response = ReadResponse::from_shared_slice(Arc::from(&b"abcdef"[..]), 2, 99);
        assert_eq!(response.bytes(), b"cdef");
    }

    #[test]
    fn shared_slice_handles_offset_past_end() {
        let response = ReadResponse::from_shared_slice(Arc::from(&b"abcdef"[..]), 99, 4);
        assert_eq!(response.bytes(), b"");
    }
}
