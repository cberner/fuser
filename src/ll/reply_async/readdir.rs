//! Response data implementation of [`crate::AsyncFilesystem::readdir`] operation to
//! send to the kernel

use std::ffi::OsStr;
use std::io::IoSlice;

use crate::FileType;
use crate::INodeNo;

use crate::ll::ioslice_concat::IosliceConcat;
use crate::ll::reply::DirEntList;
use crate::ll::reply::DirEntOffset;
use crate::ll::reply::DirEntry;
use crate::ll::reply::Response;

/// Response data from [`crate::AsyncFilesystem::readdir`] operation
#[derive(Debug)]
pub struct DirectoryResponse {
    data: DirEntList,
}

impl DirectoryResponse {
    /// Creates a new [`DirectoryResponse`] with a specified buffer size.
    pub fn new(size: usize) -> DirectoryResponse {
        DirectoryResponse {
            data: DirEntList::new(size),
        }
    }

    /// Add an entry to the directory reply buffer. Returns true if the buffer is full.
    /// A transparent offset value can be provided for each entry. The kernel uses these
    /// value to request the next entries in further readdir calls
    #[must_use]
    pub fn add<T: AsRef<OsStr>>(
        &mut self,
        ino: INodeNo,
        offset: u64,
        kind: FileType,
        name: T,
    ) -> bool {
        let name = name.as_ref();
        self.data
            .push(&DirEntry::new(ino, DirEntOffset(offset), kind, name))
    }
}

impl Response for DirectoryResponse {
    fn payload(&self) -> impl IosliceConcat {
        [IoSlice::new(self.data.as_bytes())]
    }
}
