//! Low-level filesystem operation request.
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.

use crate::fuse_abi::{fuse_in_header, fuse_opcode, InvalidOpcodeError};
use std::convert::TryFrom;
use std::{error, fmt, mem};

use super::argument::ArgumentIterator;

/// Error that may occur while reading and parsing a request from the kernel driver.
#[derive(Debug)]
pub enum RequestError {
    /// Not enough data for parsing header (short read).
    ShortReadHeader(usize),
    /// Kernel requested an unknown operation.
    UnknownOperation(u32),
    /// Not enough data for arguments (short read).
    ShortRead(usize, usize),
    /// Insufficient argument data.
    InsufficientData,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestError::ShortReadHeader(len) => write!(
                f,
                "Short read of FUSE request header ({} < {})",
                len,
                mem::size_of::<fuse_in_header>()
            ),
            RequestError::UnknownOperation(opcode) => write!(f, "Unknown FUSE opcode ({})", opcode),
            RequestError::ShortRead(len, total) => {
                write!(f, "Short read of FUSE request ({} < {})", len, total)
            }
            RequestError::InsufficientData => write!(f, "Insufficient argument data"),
        }
    }
}

impl error::Error for RequestError {}

mod op {
    use crate::fuse_abi::*;
    use std::ffi::OsStr;

    #[derive(Debug)]
    pub struct Lookup<'a> {
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct Forget<'a> {
        pub arg: &'a fuse_forget_in,
    }
    #[derive(Debug)]
    pub struct GetAttr();
    #[derive(Debug)]
    pub struct SetAttr<'a> {
        pub arg: &'a fuse_setattr_in,
    }
    #[derive(Debug)]
    pub struct ReadLink();
    #[derive(Debug)]
    pub struct SymLink<'a> {
        pub name: &'a OsStr,
        pub link: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct MkNod<'a> {
        pub arg: &'a fuse_mknod_in,
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct MkDir<'a> {
        pub arg: &'a fuse_mkdir_in,
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct Unlink<'a> {
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct RmDir<'a> {
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct Rename<'a> {
        pub arg: &'a fuse_rename_in,
        pub name: &'a OsStr,
        pub newname: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct Link<'a> {
        pub arg: &'a fuse_link_in,
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct Open<'a> {
        pub arg: &'a fuse_open_in,
    }
    #[derive(Debug)]
    pub struct Read<'a> {
        pub arg: &'a fuse_read_in,
    }
    #[derive(Debug)]
    pub struct Write<'a> {
        pub arg: &'a fuse_write_in,
        pub data: &'a [u8],
    }
    #[derive(Debug)]
    pub struct StatFs();
    #[derive(Debug)]
    pub struct Release<'a> {
        pub arg: &'a fuse_release_in,
    }
    #[derive(Debug)]
    pub struct FSync<'a> {
        pub arg: &'a fuse_fsync_in,
    }
    #[derive(Debug)]
    pub struct SetXAttr<'a> {
        pub arg: &'a fuse_setxattr_in,
        pub name: &'a OsStr,
        pub value: &'a [u8],
    }
    #[derive(Debug)]
    pub struct GetXAttr<'a> {
        pub arg: &'a fuse_getxattr_in,
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct ListXAttr<'a> {
        pub arg: &'a fuse_getxattr_in,
    }
    #[derive(Debug)]
    pub struct RemoveXAttr<'a> {
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct Flush<'a> {
        pub arg: &'a fuse_flush_in,
    }
    #[derive(Debug)]
    pub struct Init<'a> {
        pub arg: &'a fuse_init_in,
    }
    #[derive(Debug)]
    pub struct OpenDir<'a> {
        pub arg: &'a fuse_open_in,
    }
    #[derive(Debug)]
    pub struct ReadDir<'a> {
        pub arg: &'a fuse_read_in,
    }
    #[derive(Debug)]
    pub struct ReleaseDir<'a> {
        pub arg: &'a fuse_release_in,
    }
    #[derive(Debug)]
    pub struct FSyncDir<'a> {
        pub arg: &'a fuse_fsync_in,
    }
    #[derive(Debug)]
    pub struct GetLk<'a> {
        pub arg: &'a fuse_lk_in,
    }
    #[derive(Debug)]
    pub struct SetLk<'a> {
        pub arg: &'a fuse_lk_in,
    }
    #[derive(Debug)]
    pub struct SetLkW<'a> {
        pub arg: &'a fuse_lk_in,
    }
    #[derive(Debug)]
    pub struct Access<'a> {
        pub arg: &'a fuse_access_in,
    }
    #[derive(Debug)]
    pub struct Create<'a> {
        pub arg: &'a fuse_create_in,
        pub name: &'a OsStr,
    }
    #[derive(Debug)]
    pub struct Interrupt<'a> {
        pub arg: &'a fuse_interrupt_in,
    }
    #[derive(Debug)]
    pub struct BMap<'a> {
        pub arg: &'a fuse_bmap_in,
    }
    #[derive(Debug)]
    pub struct Destroy();
    #[cfg(feature = "abi-7-11")]
    #[derive(Debug)]
    pub struct IoCtl<'a> {
        pub arg: &'a fuse_ioctl_in,
        pub data: &'a [u8],
    }
    #[cfg(feature = "abi-7-11")]
    #[derive(Debug)]
    pub struct Poll<'a> {
        pub arg: &'a fuse_poll_in,
    }
    #[cfg(feature = "abi-7-15")]
    #[derive(Debug)]
    pub struct NotifyReply<'a> {
        pub data: &'a [u8],
    }
    #[cfg(feature = "abi-7-16")]
    #[derive(Debug)]
    pub struct BatchForget<'a> {
        pub arg: &'a fuse_forget_in,
        pub nodes: &'a [fuse_forget_one],
    }
    #[cfg(feature = "abi-7-19")]
    #[derive(Debug)]
    pub struct FAllocate<'a> {
        pub arg: &'a fuse_fallocate_in,
    }
    #[cfg(feature = "abi-7-21")]
    #[derive(Debug)]
    pub struct ReadDirPlus<'a> {
        pub arg: &'a fuse_read_in,
    }
    #[cfg(feature = "abi-7-23")]
    #[derive(Debug)]
    pub struct Rename2<'a> {
        pub arg: &'a fuse_rename2_in,
        pub name: &'a OsStr,
        pub newname: &'a OsStr,
    }
    #[cfg(feature = "abi-7-24")]
    #[derive(Debug)]
    pub struct Lseek<'a> {
        pub arg: &'a fuse_lseek_in,
    }
    #[cfg(feature = "abi-7-28")]
    #[derive(Debug)]
    pub struct CopyFileRange<'a> {
        pub arg: &'a fuse_copy_file_range_in,
    }

    #[cfg(target_os = "macos")]
    #[derive(Debug)]
    pub struct SetVolName<'a> {
        pub name: &'a OsStr,
    }
    #[cfg(target_os = "macos")]
    #[derive(Debug)]
    pub struct GetXTimes();
    #[cfg(target_os = "macos")]
    #[derive(Debug)]
    pub struct Exchange<'a> {
        pub arg: &'a fuse_exchange_in,
        pub oldname: &'a OsStr,
        pub newname: &'a OsStr,
    }

    #[cfg(feature = "abi-7-12")]
    #[derive(Debug)]
    pub struct CuseInit<'a> {
        pub arg: &'a fuse_init_in,
    }
}
use op::*;

/// Filesystem operation (and arguments) the kernel driver wants us to perform. The fields of each
/// variant needs to match the actual arguments the kernel driver sends for the specific operation.
#[derive(Debug)]
pub enum Operation<'a> {
    Lookup(Lookup<'a>),
    Forget(Forget<'a>),
    GetAttr(GetAttr),
    SetAttr(SetAttr<'a>),
    ReadLink(ReadLink),
    SymLink(SymLink<'a>),
    MkNod(MkNod<'a>),
    MkDir(MkDir<'a>),
    Unlink(Unlink<'a>),
    RmDir(RmDir<'a>),
    Rename(Rename<'a>),
    Link(Link<'a>),
    Open(Open<'a>),
    Read(Read<'a>),
    Write(Write<'a>),
    StatFs(StatFs),
    Release(Release<'a>),
    FSync(FSync<'a>),
    SetXAttr(SetXAttr<'a>),
    GetXAttr(GetXAttr<'a>),
    ListXAttr(ListXAttr<'a>),
    RemoveXAttr(RemoveXAttr<'a>),
    Flush(Flush<'a>),
    Init(Init<'a>),
    OpenDir(OpenDir<'a>),
    ReadDir(ReadDir<'a>),
    ReleaseDir(ReleaseDir<'a>),
    FSyncDir(FSyncDir<'a>),
    GetLk(GetLk<'a>),
    SetLk(SetLk<'a>),
    SetLkW(SetLkW<'a>),
    Access(Access<'a>),
    Create(Create<'a>),
    Interrupt(Interrupt<'a>),
    BMap(BMap<'a>),
    Destroy(Destroy),
    #[cfg(feature = "abi-7-11")]
    IoCtl(IoCtl<'a>),
    #[cfg(feature = "abi-7-11")]
    Poll(Poll<'a>),
    #[cfg(feature = "abi-7-15")]
    NotifyReply(NotifyReply<'a>),
    #[cfg(feature = "abi-7-16")]
    BatchForget(BatchForget<'a>),
    #[cfg(feature = "abi-7-19")]
    FAllocate(FAllocate<'a>),
    #[cfg(feature = "abi-7-21")]
    ReadDirPlus(ReadDirPlus<'a>),
    #[cfg(feature = "abi-7-23")]
    Rename2(Rename2<'a>),
    #[cfg(feature = "abi-7-24")]
    Lseek(Lseek<'a>),
    #[cfg(feature = "abi-7-28")]
    CopyFileRange(CopyFileRange<'a>),

    #[cfg(target_os = "macos")]
    SetVolName(SetVolName<'a>),
    #[cfg(target_os = "macos")]
    GetXTimes(GetXTimes),
    #[cfg(target_os = "macos")]
    Exchange(Exchange<'a>),

    #[cfg(feature = "abi-7-12")]
    CuseInit(CuseInit<'a>),
}

impl<'a> fmt::Display for Operation<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Lookup(x) => write!(f, "LOOKUP name {:?}", x.name),
            Operation::Forget(x) => write!(f, "FORGET nlookup {}", x.arg.nlookup),
            Operation::GetAttr(_) => write!(f, "GETATTR"),
            Operation::SetAttr(x) => write!(f, "SETATTR valid {:#x}", x.arg.valid),
            Operation::ReadLink(_) => write!(f, "READLINK"),
            Operation::SymLink(x) => write!(f, "SYMLINK name {:?}, link {:?}", x.name, x.link),
            Operation::MkNod(x) => write!(f, "MKNOD name {:?}, mode {:#05o}, rdev {}", x.name, x.arg.mode, x.arg.rdev),
            Operation::MkDir(x) => write!(f, "MKDIR name {:?}, mode {:#05o}", x.name, x.arg.mode),
            Operation::Unlink(x) => write!(f, "UNLINK name {:?}", x.name),
            Operation::RmDir(x) => write!(f, "RMDIR name {:?}", x.name),
            Operation::Rename(x) => write!(f, "RENAME name {:?}, newdir {:#018x}, newname {:?}", x.name, x.arg.newdir, x.newname),
            Operation::Link(x) => write!(f, "LINK name {:?}, oldnodeid {:#018x}", x.name, x.arg.oldnodeid),
            Operation::Open(x) => write!(f, "OPEN flags {:#x}", x.arg.flags),
            Operation::Read(x) => write!(f, "READ fh {}, offset {}, size {}", x.arg.fh, x.arg.offset, x.arg.size),
            Operation::Write(x) => write!(f, "WRITE fh {}, offset {}, size {}, write flags {:#x}", x.arg.fh, x.arg.offset,x. arg.size, x.arg.write_flags),
            Operation::StatFs(_) => write!(f, "STATFS"),
            Operation::Release(x) => write!(f, "RELEASE fh {}, flags {:#x}, release flags {:#x}, lock owner {}",x. arg.fh,x. arg.flags, x.arg.release_flags,x. arg.lock_owner),
            Operation::FSync(x) => write!(f, "FSYNC fh {}, fsync flags {:#x}", x.arg.fh, x.arg.fsync_flags),
            Operation::SetXAttr(x) => write!(f, "SETXATTR name {:?}, size {}, flags {:#x}",x. name, x.arg.size, x.arg.flags),
            Operation::GetXAttr(x) => write!(f, "GETXATTR name {:?}, size {}", x.name, x.arg.size),
            Operation::ListXAttr(x) => write!(f, "LISTXATTR size {}", x.arg.size),
            Operation::RemoveXAttr(x) => write!(f, "REMOVEXATTR name {:?}",x. name),
            Operation::Flush(x) => write!(f, "FLUSH fh {}, lock owner {}",x. arg.fh, x.arg.lock_owner),
            Operation::Init(x) => write!(f, "INIT kernel ABI {}.{}, flags {:#x}, max readahead {}",x. arg.major, x.arg.minor, x.arg.flags, x.arg.max_readahead),
            Operation::OpenDir(x) => write!(f, "OPENDIR flags {:#x}", x.arg.flags),
            Operation::ReadDir(x) => write!(f, "READDIR fh {}, offset {}, size {}",x. arg.fh, x.arg.offset, x.arg.size),
            Operation::ReleaseDir(x) => write!(f, "RELEASEDIR fh {}, flags {:#x}, release flags {:#x}, lock owner {}", x.arg.fh,x. arg.flags,x. arg.release_flags, x.arg.lock_owner),
            Operation::FSyncDir(x) => write!(f, "FSYNCDIR fh {}, fsync flags {:#x}", x.arg.fh, x.arg.fsync_flags),
            Operation::GetLk(x) => write!(f, "GETLK fh {}, lock owner {}", x.arg.fh, x.arg.owner),
            Operation::SetLk(x) => write!(f, "SETLK fh {}, lock owner {}", x.arg.fh,x. arg.owner),
            Operation::SetLkW(x) => write!(f, "SETLKW fh {}, lock owner {}",x. arg.fh,x. arg.owner),
            Operation::Access(x) => write!(f, "ACCESS mask {:#05o}",x. arg.mask),
            Operation::Create(x) => write!(f, "CREATE name {:?}, mode {:#05o}, flags {:#x}",x. name, x.arg.mode, x.arg.flags),
            Operation::Interrupt(x) => write!(f, "INTERRUPT unique {}",x. arg.unique),
            Operation::BMap(x) => write!(f, "BMAP blocksize {}, ids {}", x.arg.blocksize, x.arg.block),
            Operation::Destroy(_) => write!(f, "DESTROY"),
            #[cfg(feature = "abi-7-11")]
            Operation::IoCtl(x) => write!(f, "IOCTL fh {}, cmd {}, data size {}, flags {:#x}", x.arg.fh, x.arg.cmd, x.data.len(), x.arg.flags),
            #[cfg(feature = "abi-7-11")]
            Operation::Poll(x) => write!(f, "POLL fh {}, flags {:#x}", x.arg.fh, x.arg.flags),
            #[cfg(feature = "abi-7-15")]
            Operation::NotifyReply(x) => write!(f, "NOTIFYREPLY data len {}", x.data.len()),
            #[cfg(feature = "abi-7-16")]
            Operation::BatchForget(x) => write!(f, "BATCHFORGET nodes {}, nlookup {}", x.nodes.len(),x. arg.nlookup),
            #[cfg(feature = "abi-7-19")]
            Operation::FAllocate(_) => write!(f, "FALLOCATE"),
            #[cfg(feature = "abi-7-21")]
            Operation::ReadDirPlus(x) => write!(f, "READDIRPLUS fh {}, offset {}, size {}", x.arg.fh, x.arg.offset,x. arg.size),
            #[cfg(feature = "abi-7-23")]
            Operation::Rename2(x) => write!(f, "RENAME2 name {:?}, newdir {:#018x}, newname {:?}", x.name, x.arg.newdir,x. newname),
            #[cfg(feature = "abi-7-24")]
            Operation::Lseek(x) => write!(f, "LSEEK fh {}, offset {}, whence {}", x.arg.fh, x.arg.offset, x.arg.whence),
            #[cfg(feature = "abi-7-28")]
            Operation::CopyFileRange(x) => write!(f, "COPY_FILE_RANGE fh_in {}, offset_in {}, fh_out {}, offset_out {}, inode_out {}, len {}",x. arg.fh_in, x.arg.off_in,x. arg.fh_out, x.arg.off_out, x.arg.nodeid_out, x.arg.len),

            #[cfg(target_os = "macos")]
            Operation::SetVolName(x) => write!(f, "SETVOLNAME name {:?}", x.name),
            #[cfg(target_os = "macos")]
            Operation::GetXTimes(_) => write!(f, "GETXTIMES"),
            #[cfg(target_os = "macos")]
            Operation::Exchange(x) => write!(f, "EXCHANGE olddir {:#018x}, oldname {:?}, newdir {:#018x}, newname {:?}, options {:#x}", x.arg.olddir,x. oldname,x. arg.newdir,x. newname,x. arg.options),

            #[cfg(feature = "abi-7-12")]
            Operation::CuseInit(x) => write!(f, "CUSE_INIT kernel ABI {}.{}, flags {:#x}, max readahead {}",x. arg.major, x.arg.minor,x. arg.flags,x. arg.max_readahead),
        }
    }
}

impl<'a> Operation<'a> {
    fn parse(opcode: &fuse_opcode, data: &mut ArgumentIterator<'a>) -> Option<Self> {
        Some(match opcode {
            fuse_opcode::FUSE_LOOKUP => Operation::Lookup(Lookup {
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_FORGET => Operation::Forget(Forget { arg: data.fetch()? }),
            fuse_opcode::FUSE_GETATTR => Operation::GetAttr(GetAttr()),
            fuse_opcode::FUSE_SETATTR => Operation::SetAttr(SetAttr { arg: data.fetch()? }),
            fuse_opcode::FUSE_READLINK => Operation::ReadLink(ReadLink {}),
            fuse_opcode::FUSE_SYMLINK => Operation::SymLink(SymLink {
                name: data.fetch_str()?,
                link: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_MKNOD => Operation::MkNod(MkNod {
                arg: data.fetch()?,
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_MKDIR => Operation::MkDir(MkDir {
                arg: data.fetch()?,
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_UNLINK => Operation::Unlink(Unlink {
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_RMDIR => Operation::RmDir(RmDir {
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_RENAME => Operation::Rename(Rename {
                arg: data.fetch()?,
                name: data.fetch_str()?,
                newname: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_LINK => Operation::Link(Link {
                arg: data.fetch()?,
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_OPEN => Operation::Open(Open { arg: data.fetch()? }),
            fuse_opcode::FUSE_READ => Operation::Read(Read { arg: data.fetch()? }),
            fuse_opcode::FUSE_WRITE => Operation::Write(Write {
                arg: data.fetch()?,
                data: data.fetch_all(),
            }),
            fuse_opcode::FUSE_STATFS => Operation::StatFs(StatFs {}),
            fuse_opcode::FUSE_RELEASE => Operation::Release(Release { arg: data.fetch()? }),
            fuse_opcode::FUSE_FSYNC => Operation::FSync(FSync { arg: data.fetch()? }),
            fuse_opcode::FUSE_SETXATTR => Operation::SetXAttr(SetXAttr {
                arg: data.fetch()?,
                name: data.fetch_str()?,
                value: data.fetch_all(),
            }),
            fuse_opcode::FUSE_GETXATTR => Operation::GetXAttr(GetXAttr {
                arg: data.fetch()?,
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_LISTXATTR => Operation::ListXAttr(ListXAttr { arg: data.fetch()? }),
            fuse_opcode::FUSE_REMOVEXATTR => Operation::RemoveXAttr(RemoveXAttr {
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_FLUSH => Operation::Flush(Flush { arg: data.fetch()? }),
            fuse_opcode::FUSE_INIT => Operation::Init(Init { arg: data.fetch()? }),
            fuse_opcode::FUSE_OPENDIR => Operation::OpenDir(OpenDir { arg: data.fetch()? }),
            fuse_opcode::FUSE_READDIR => Operation::ReadDir(ReadDir { arg: data.fetch()? }),
            fuse_opcode::FUSE_RELEASEDIR => {
                Operation::ReleaseDir(ReleaseDir { arg: data.fetch()? })
            }
            fuse_opcode::FUSE_FSYNCDIR => Operation::FSyncDir(FSyncDir { arg: data.fetch()? }),
            fuse_opcode::FUSE_GETLK => Operation::GetLk(GetLk { arg: data.fetch()? }),
            fuse_opcode::FUSE_SETLK => Operation::SetLk(SetLk { arg: data.fetch()? }),
            fuse_opcode::FUSE_SETLKW => Operation::SetLkW(SetLkW { arg: data.fetch()? }),
            fuse_opcode::FUSE_ACCESS => Operation::Access(Access { arg: data.fetch()? }),
            fuse_opcode::FUSE_CREATE => Operation::Create(Create {
                arg: data.fetch()?,
                name: data.fetch_str()?,
            }),
            fuse_opcode::FUSE_INTERRUPT => Operation::Interrupt(Interrupt { arg: data.fetch()? }),
            fuse_opcode::FUSE_BMAP => Operation::BMap(BMap { arg: data.fetch()? }),
            fuse_opcode::FUSE_DESTROY => Operation::Destroy(Destroy {}),
            #[cfg(feature = "abi-7-11")]
            fuse_opcode::FUSE_IOCTL => Operation::IoCtl(IoCtl {
                arg: data.fetch()?,
                data: data.fetch_all(),
            }),
            #[cfg(feature = "abi-7-11")]
            fuse_opcode::FUSE_POLL => Operation::Poll(Poll { arg: data.fetch()? }),
            #[cfg(feature = "abi-7-15")]
            fuse_opcode::FUSE_NOTIFY_REPLY => Operation::NotifyReply(NotifyReply {
                data: data.fetch_all(),
            }),
            #[cfg(feature = "abi-7-16")]
            // TODO: parse the nodes
            fuse_opcode::FUSE_BATCH_FORGET => Operation::BatchForget(BatchForget {
                arg: data.fetch()?,
                nodes: &[],
            }),
            #[cfg(feature = "abi-7-19")]
            fuse_opcode::FUSE_FALLOCATE => Operation::FAllocate(FAllocate { arg: data.fetch()? }),
            #[cfg(feature = "abi-7-21")]
            fuse_opcode::FUSE_READDIRPLUS => {
                Operation::ReadDirPlus(ReadDirPlus { arg: data.fetch()? })
            }
            #[cfg(feature = "abi-7-23")]
            fuse_opcode::FUSE_RENAME2 => Operation::Rename2(Rename2 {
                arg: data.fetch()?,
                name: data.fetch_str()?,
                newname: data.fetch_str()?,
            }),
            #[cfg(feature = "abi-7-24")]
            fuse_opcode::FUSE_LSEEK => Operation::Lseek(Lseek { arg: data.fetch()? }),
            #[cfg(feature = "abi-7-28")]
            fuse_opcode::FUSE_COPY_FILE_RANGE => {
                Operation::CopyFileRange(CopyFileRange { arg: data.fetch()? })
            }

            #[cfg(target_os = "macos")]
            fuse_opcode::FUSE_SETVOLNAME => Operation::SetVolName(SetVolName {
                name: data.fetch_str()?,
            }),
            #[cfg(target_os = "macos")]
            fuse_opcode::FUSE_GETXTIMES => Operation::GetXTimes,
            #[cfg(target_os = "macos")]
            fuse_opcode::FUSE_EXCHANGE => Operation::Exchange(Exchange {
                arg: data.fetch()?,
                oldname: data.fetch_str()?,
                newname: data.fetch_str()?,
            }),

            #[cfg(feature = "abi-7-12")]
            fuse_opcode::CUSE_INIT => Operation::CuseInit(CuseInit { arg: data.fetch()? }),
        })
    }
}

/// Low-level request of a filesystem operation the kernel driver wants to perform.
#[derive(Debug)]
pub struct Request<'a> {
    header: &'a fuse_in_header,
    operation: Operation<'a>,
}

impl<'a> fmt::Display for Request<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FUSE({:3}) ino {:#018x}: {}",
            self.header.unique, self.header.nodeid, self.operation
        )
    }
}

impl<'a> TryFrom<&'a [u8]> for Request<'a> {
    type Error = RequestError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        // Parse a raw packet as sent by the kernel driver into typed data. Every request always
        // begins with a `fuse_in_header` struct followed by arguments depending on the opcode.
        let data_len = data.len();
        let mut data = ArgumentIterator::new(data);
        // Parse header
        let header: &fuse_in_header = data
            .fetch()
            .ok_or_else(|| RequestError::ShortReadHeader(data.len()))?;
        // Parse/check opcode
        let opcode = fuse_opcode::try_from(header.opcode)
            .map_err(|_: InvalidOpcodeError| RequestError::UnknownOperation(header.opcode))?;
        // Check data size
        if data_len < header.len as usize {
            return Err(RequestError::ShortRead(data_len, header.len as usize));
        }
        // Parse/check operation arguments
        let operation =
            Operation::parse(&opcode, &mut data).ok_or(RequestError::InsufficientData)?;
        Ok(Self { header, operation })
    }
}

impl<'a> Request<'a> {
    /// Returns the unique identifier of this request.
    ///
    /// The FUSE kernel driver assigns a unique id to every concurrent request. This allows to
    /// distinguish between multiple concurrent requests. The unique id of a request may be
    /// reused in later requests after it has completed.
    #[inline]
    pub fn unique(&self) -> u64 {
        self.header.unique
    }

    /// Returns the node id of the inode this request is targeted to.
    #[inline]
    pub fn nodeid(&self) -> u64 {
        self.header.nodeid
    }

    /// Returns the UID that the process that triggered this request runs under.
    #[inline]
    pub fn uid(&self) -> u32 {
        self.header.uid
    }

    /// Returns the GID that the process that triggered this request runs under.
    #[inline]
    pub fn gid(&self) -> u32 {
        self.header.gid
    }

    /// Returns the PID of the process that triggered this request.
    #[inline]
    pub fn pid(&self) -> u32 {
        self.header.pid
    }

    /// Returns the filesystem operation (and its arguments) of this request.
    #[inline]
    pub fn operation(&self) -> &Operation<'_> {
        &self.operation
    }
}

#[cfg(test)]
mod tests {
    use super::super::test::AlignedData;
    use super::*;
    use std::ffi::OsStr;

    #[cfg(target_endian = "big")]
    const INIT_REQUEST: AlignedData<[u8; 56]> = AlignedData([
        0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x1a, // len, opcode
        0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xd0, 0x0d, // unique
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // nodeid
        0xc0, 0x01, 0xd0, 0x0d, 0xc0, 0x01, 0xca, 0xfe, // uid, gid
        0xc0, 0xde, 0xba, 0x5e, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, // major, minor
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // max_readahead, flags
    ]);

    #[cfg(target_endian = "little")]
    const INIT_REQUEST: AlignedData<[u8; 56]> = AlignedData([
        0x38, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, // len, opcode
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // major, minor
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max_readahead, flags
    ]);

    #[cfg(target_endian = "big")]
    const MKNOD_REQUEST: AlignedData<[u8; 56]> = [
        0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x08, // len, opcode
        0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xd0, 0x0d, // unique
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // nodeid
        0xc0, 0x01, 0xd0, 0x0d, 0xc0, 0x01, 0xca, 0xfe, // uid, gid
        0xc0, 0xde, 0xba, 0x5e, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0x00, 0x00, 0x01, 0xa4, 0x00, 0x00, 0x00, 0x00, // mode, rdev
        0x66, 0x6f, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x00, // name
    ];

    #[cfg(all(target_endian = "little", not(feature = "abi-7-12")))]
    const MKNOD_REQUEST: AlignedData<[u8; 56]> = AlignedData([
        0x38, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // len, opcode
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mode, rdev
        0x66, 0x6f, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x00, // name
    ]);

    #[cfg(all(target_endian = "little", feature = "abi-7-12"))]
    const MKNOD_REQUEST: AlignedData<[u8; 64]> = AlignedData([
        0x38, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // len, opcode
        0x0d, 0xf0, 0xad, 0xba, 0xef, 0xbe, 0xad, 0xde, // unique
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // nodeid
        0x0d, 0xd0, 0x01, 0xc0, 0xfe, 0xca, 0x01, 0xc0, // uid, gid
        0x5e, 0xba, 0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, // pid, padding
        0xa4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mode, rdev
        0xed, 0x01, 0x00, 0x00, 0xe7, 0x03, 0x00, 0x00, // umask, padding
        0x66, 0x6f, 0x6f, 0x2e, 0x74, 0x78, 0x74, 0x00, // name
    ]);

    #[test]
    fn short_read_header() {
        match Request::try_from(&INIT_REQUEST[..20]) {
            Err(RequestError::ShortReadHeader(20)) => (),
            _ => panic!("Unexpected request parsing result"),
        }
    }

    #[test]
    fn short_read() {
        match Request::try_from(&INIT_REQUEST[..48]) {
            Err(RequestError::ShortRead(48, 56)) => (),
            _ => panic!("Unexpected request parsing result"),
        }
    }

    #[test]
    fn init() {
        let req = Request::try_from(&INIT_REQUEST[..]).unwrap();
        assert_eq!(req.header.len, 56);
        assert_eq!(req.header.opcode, 26);
        assert_eq!(req.unique(), 0xdead_beef_baad_f00d);
        assert_eq!(req.nodeid(), 0x1122_3344_5566_7788);
        assert_eq!(req.uid(), 0xc001_d00d);
        assert_eq!(req.gid(), 0xc001_cafe);
        assert_eq!(req.pid(), 0xc0de_ba5e);
        match req.operation() {
            Operation::Init(x) => {
                assert_eq!(x.arg.major, 7);
                assert_eq!(x.arg.minor, 8);
                assert_eq!(x.arg.max_readahead, 4096);
            }
            _ => panic!("Unexpected request operation"),
        }
    }

    #[test]
    fn mknod() {
        let req = Request::try_from(&MKNOD_REQUEST[..]).unwrap();
        assert_eq!(req.header.len, 56);
        assert_eq!(req.header.opcode, 8);
        assert_eq!(req.unique(), 0xdead_beef_baad_f00d);
        assert_eq!(req.nodeid(), 0x1122_3344_5566_7788);
        assert_eq!(req.uid(), 0xc001_d00d);
        assert_eq!(req.gid(), 0xc001_cafe);
        assert_eq!(req.pid(), 0xc0de_ba5e);
        match req.operation() {
            Operation::MkNod(x) => {
                assert_eq!(x.arg.mode, 0o644);
                #[cfg(feature = "abi-7-12")]
                assert_eq!(x.arg.umask, 0o755);
                #[cfg(feature = "abi-7-12")]
                assert_eq!(x.arg.padding, 999);
                assert_eq!(x.name, OsStr::new("foo.txt"));
            }
            _ => panic!("Unexpected request operation"),
        }
    }
}
