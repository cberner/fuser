//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use crate::ll::{Errno, Response, fuse_abi as abi};
use log::{debug, error, warn};
use std::convert::TryFrom;
#[cfg(feature = "abi-7-28")]
use std::convert::TryInto;
use std::path::Path;

use crate::Filesystem;
use crate::PollHandle;
use crate::channel::ChannelSender;
use crate::ll::Request as _;
#[cfg(feature = "abi-7-21")]
use crate::reply::ReplyDirectoryPlus;
use crate::reply::{Reply, ReplyDirectory, ReplySender};
use crate::session::{Session, SessionACL};
use crate::{KernelConfig, ll};

/// Request data structure
#[derive(Debug)]
pub struct Request<'a> {
    /// Channel sender for sending the reply
    ch: ChannelSender,
    /// Request raw data
    #[allow(unused)]
    data: &'a [u8],
    /// Parsed request
    request: ll::AnyRequest<'a>,
}

impl<'a> Request<'a> {
    /// Create a new request from the given data
    pub(crate) fn new(ch: ChannelSender, data: &'a [u8]) -> Option<Request<'a>> {
        let request = match ll::AnyRequest::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                error!("{err}");
                return None;
            }
        };

        Some(Self { ch, data, request })
    }

    /// Dispatch request to the given filesystem.
    /// This calls the appropriate filesystem operation method for the
    /// request and sends back the returned reply to the kernel
    pub(crate) fn dispatch<FS: Filesystem>(&self, se: &mut Session<FS>) {
        debug!("{}", self.request);
        let unique = self.request.unique();

        let res = match self.dispatch_req(se) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => self.request.reply_err(errno),
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}");
        }
    }

    /// Dispatch request with explicit session context instead of Session struct.
    /// This is used by multi-threaded session to avoid unsafe copying of FS.
    pub(crate) fn dispatch_with_context<FS: Filesystem>(
        &self,
        filesystem: &mut FS,
        allowed: &SessionACL,
        session_owner: u32,
        proto_major: &mut u32,
        proto_minor: &mut u32,
        initialized: &mut bool,
        destroyed: bool,
    ) {
        debug!("{}", self.request);
        let unique = self.request.unique();

        let res = match self.dispatch_req_with_context(
            filesystem,
            allowed,
            session_owner,
            proto_major,
            proto_minor,
            initialized,
            destroyed
        ) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => self.request.reply_err(errno),
        }
        .with_iovec(unique, |iov| self.ch.send(iov));

        if let Err(err) = res {
            warn!("Request {unique:?}: Failed to send reply: {err}");
        }
    }

    /// Original dispatch_req that uses Session struct for backward compatibility.
    fn dispatch_req<FS: Filesystem>(
        &self,
        se: &mut Session<FS>,
    ) -> Result<Option<Response<'_>>, Errno> {
        self.dispatch_req_with_context(
            &mut se.filesystem,
            &se.allowed,
            se.session_owner,
            &mut se.proto_major,
            &mut se.proto_minor,
            &mut se.initialized,
            se.destroyed,
        )
    }

    /// Internal dispatch request that uses explicit parameters instead of Session struct.
    fn dispatch_req_with_context<FS: Filesystem>(
        &self,
        filesystem: &mut FS,
        allowed: &SessionACL,
        session_owner: u32,
        proto_major: &mut u32,
        proto_minor: &mut u32,
        initialized: &mut bool,
        destroyed: bool,
    ) -> Result<Option<Response<'_>>, Errno> {
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        // Implement allow_root & access check for auto_unmount
        if (*allowed == SessionACL::RootAndOwner
            && self.request.uid() != session_owner
            && self.request.uid() != 0)
            || (*allowed == SessionACL::Owner && self.request.uid() != session_owner)
        {
            #[cfg(feature = "abi-7-21")]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::ReadDirPlus(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
            #[cfg(not(feature = "abi-7-21"))]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::BatchForget(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
        }
        match op {
            // Filesystem initialization
            ll::Operation::Init(x) => {
                // We don't support ABI versions before 7.6
                let v = x.version();
                if v < ll::Version(7, 6) {
                    error!("Unsupported FUSE ABI version {v}");
                    return Err(Errno::EPROTO);
                }
                // Remember ABI version supported by kernel
                *proto_major = v.major();
                *proto_minor = v.minor();

                let mut config = KernelConfig::new(x.capabilities(), x.max_readahead());
                // Call filesystem init method and give it a chance to return an error
                filesystem
                    .init(self, &mut config)
                    .map_err(Errno::from_i32)?;

                // Reply with our desired version and settings. If the kernel supports a
                // larger major version, it'll re-send a matching init message. If it
                // supports only lower major versions, we replied with an error above.
                debug!(
                    "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                    abi::FUSE_KERNEL_VERSION,
                    abi::FUSE_KERNEL_MINOR_VERSION,
                    x.capabilities() & config.requested,
                    config.max_readahead,
                    config.max_write
                );
                *initialized = true;
                return Ok(Some(x.reply(&config)));
            }
            // Any operation is invalid before initialization
            _ if !*initialized => {
                warn!("Ignoring FUSE operation before init: {}", self.request);
                return Err(Errno::EIO);
            }
            // Filesystem destroyed
            ll::Operation::Destroy(x) => {
                filesystem.destroy();
                // Note: destroyed is not a &mut because it's a terminal operation
                return Ok(Some(x.reply()));
            }
            // Any operation is invalid after destroy
            _ if destroyed => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                return Err(Errno::EIO);
            }

            ll::Operation::Interrupt(_) => {
                // TODO: handle FUSE_INTERRUPT
                return Err(Errno::ENOSYS);
            }

            ll::Operation::Lookup(x) => {
                filesystem.lookup(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Forget(x) => {
                filesystem
                    .forget(self, self.request.nodeid().into(), x.nlookup()); // no reply
            }
            ll::Operation::GetAttr(_attr) => {
                filesystem.getattr(
                    self,
                    self.request.nodeid().into(),
                    _attr.file_handle().map(std::convert::Into::into),
                    self.reply(),
                );
            }
            ll::Operation::SetAttr(x) => {
                filesystem.setattr(
                    self,
                    self.request.nodeid().into(),
                    x.mode(),
                    x.uid(),
                    x.gid(),
                    x.size(),
                    x.atime(),
                    x.mtime(),
                    x.ctime(),
                    x.file_handle().map(std::convert::Into::into),
                    x.crtime(),
                    x.chgtime(),
                    x.bkuptime(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::ReadLink(_) => {
                filesystem
                    .readlink(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::MkNod(x) => {
                filesystem.mknod(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.rdev(),
                    self.reply(),
                );
            }
            ll::Operation::MkDir(x) => {
                filesystem.mkdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    self.reply(),
                );
            }
            ll::Operation::Unlink(x) => {
                filesystem.unlink(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::RmDir(x) => {
                filesystem.rmdir(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::SymLink(x) => {
                filesystem.symlink(
                    self,
                    self.request.nodeid().into(),
                    x.link_name().as_ref(),
                    Path::new(x.target()),
                    self.reply(),
                );
            }
            ll::Operation::Rename(x) => {
                filesystem.rename(
                    self,
                    self.request.nodeid().into(),
                    x.src().name.as_ref(),
                    x.dest().dir.into(),
                    x.dest().name.as_ref(),
                    0,
                    self.reply(),
                );
            }
            ll::Operation::Link(x) => {
                filesystem.link(
                    self,
                    x.inode_no().into(),
                    self.request.nodeid().into(),
                    x.dest().name.as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Open(x) => {
                filesystem
                    .open(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::Read(x) => {
                filesystem.read(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.size(),
                    x.flags(),
                    x.lock_owner().map(std::convert::Into::into),
                    self.reply(),
                );
            }
            ll::Operation::Write(x) => {
                filesystem.write(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.data(),
                    x.write_flags(),
                    x.flags(),
                    x.lock_owner().map(std::convert::Into::into),
                    self.reply(),
                );
            }
            ll::Operation::Flush(x) => {
                filesystem.flush(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    self.reply(),
                );
            }
            ll::Operation::Release(x) => {
                filesystem.release(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.lock_owner().map(std::convert::Into::into),
                    x.flush(),
                    self.reply(),
                );
            }
            ll::Operation::FSync(x) => {
                filesystem.fsync(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::OpenDir(x) => {
                filesystem
                    .opendir(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::ReadDir(x) => {
                filesystem.readdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectory::new(
                        self.request.unique().into(),
                        self.ch.clone(),
                        x.size() as usize,
                    ),
                );
            }
            ll::Operation::ReleaseDir(x) => {
                filesystem.releasedir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::FSyncDir(x) => {
                filesystem.fsyncdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::StatFs(_) => {
                filesystem
                    .statfs(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::SetXAttr(x) => {
                filesystem.setxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.value(),
                    x.flags(),
                    x.position(),
                    self.reply(),
                );
            }
            ll::Operation::GetXAttr(x) => {
                filesystem.getxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.size_u32(),
                    self.reply(),
                );
            }
            ll::Operation::ListXAttr(x) => {
                filesystem
                    .listxattr(self, self.request.nodeid().into(), x.size(), self.reply());
            }
            ll::Operation::RemoveXAttr(x) => {
                filesystem.removexattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    self.reply(),
                );
            }
            ll::Operation::Access(x) => {
                filesystem
                    .access(self, self.request.nodeid().into(), x.mask(), self.reply());
            }
            ll::Operation::Create(x) => {
                filesystem.create(
                    self,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::GetLk(x) => {
                filesystem.getlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    self.reply(),
                );
            }
            ll::Operation::SetLk(x) => {
                filesystem.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    false,
                    self.reply(),
                );
            }
            ll::Operation::SetLkW(x) => {
                filesystem.setlk(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    true,
                    self.reply(),
                );
            }
            ll::Operation::BMap(x) => {
                filesystem.bmap(
                    self,
                    self.request.nodeid().into(),
                    x.block_size(),
                    x.block(),
                    self.reply(),
                );
            }

            ll::Operation::IoCtl(x) => {
                if x.unrestricted() {
                    return Err(Errno::ENOSYS);
                }
                filesystem.ioctl(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.command(),
                    x.in_data(),
                    x.out_size(),
                    self.reply(),
                );
            }
            ll::Operation::Poll(x) => {
                let ph = PollHandle::new(self.ch.clone(), x.kernel_handle());

                filesystem.poll(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    ph,
                    x.events(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::NotifyReply(_) => {
                // TODO: handle FUSE_NOTIFY_REPLY
                return Err(Errno::ENOSYS);
            }
            ll::Operation::BatchForget(x) => {
                filesystem.batch_forget(self, x.nodes()); // no reply
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                filesystem.fallocate(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.len(),
                    x.mode(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(x) => {
                filesystem.readdirplus(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectoryPlus::new(
                        self.request.unique().into(),
                        self.ch.clone(),
                        x.size() as usize,
                    ),
                );
            }
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(x) => {
                filesystem.rename(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.flags(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(x) => {
                filesystem.lseek(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.whence(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-28")]
            ll::Operation::CopyFileRange(x) => {
                let (i, o) = (x.src(), x.dest());
                filesystem.copy_file_range(
                    self,
                    i.inode.into(),
                    i.file_handle.into(),
                    i.offset,
                    o.inode.into(),
                    o.file_handle.into(),
                    o.offset,
                    x.len(),
                    x.flags().try_into().unwrap(),
                    self.reply(),
                );
            }
            #[cfg(target_os = "macos")]
            ll::Operation::SetVolName(x) => {
                filesystem.setvolname(self, x.name(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(x) => {
                filesystem
                    .getxtimes(self, x.nodeid().into(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::Exchange(x) => {
                filesystem.exchange(
                    self,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.options(),
                    self.reply(),
                );
            }

            ll::Operation::CuseInit(_) => {
                // TODO: handle CUSE_INIT
                return Err(Errno::ENOSYS);
            }
        }
        Ok(None)
    }

    /// Create a reply object for this request that can be passed to the filesystem
    /// implementation and makes sure that a request is replied exactly once
    fn reply<T: Reply>(&self) -> T {
        Reply::new(self.request.unique().into(), self.ch.clone())
    }

    /// Returns the unique identifier of this request
    #[inline]
    pub fn unique(&self) -> u64 {
        self.request.unique().into()
    }

    /// Returns the uid of this request
    #[inline]
    pub fn uid(&self) -> u32 {
        self.request.uid()
    }

    /// Returns the gid of this request
    #[inline]
    pub fn gid(&self) -> u32 {
        self.request.gid()
    }

    /// Returns the pid of this request
    #[inline]
    pub fn pid(&self) -> u32 {
        self.request.pid()
    }
}
