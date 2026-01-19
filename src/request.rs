//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use std::convert::TryFrom;
use std::path::Path;

use log::debug;
use log::error;
use log::warn;

use crate::Filesystem;
use crate::PollHandle;
use crate::RenameFlags;
use crate::Request;
use crate::channel::ChannelSender;
use crate::ll;
use crate::ll::Errno;
use crate::ll::Request as _;
use crate::ll::Response;
use crate::reply::Reply;
use crate::reply::ReplyDirectory;
use crate::reply::ReplyDirectoryPlus;
use crate::reply::ReplyRaw;
use crate::reply::ReplySender;
use crate::session::Session;
use crate::session::SessionACL;

/// Request data structure
#[derive(Debug)]
pub(crate) struct RequestWithSender<'a> {
    /// Channel sender for sending the reply
    ch: ChannelSender,
    /// Parsed request
    request: ll::AnyRequest<'a>,
}

impl<'a> RequestWithSender<'a> {
    /// Create a new request from the given data
    pub(crate) fn new(ch: ChannelSender, data: &'a [u8]) -> Option<RequestWithSender<'a>> {
        let request = match ll::AnyRequest::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                error!("{err}");
                return None;
            }
        };

        Some(Self { ch, request })
    }

    /// Dispatch request to the given filesystem.
    /// This calls the appropriate filesystem operation method for the
    /// request and sends back the returned reply to the kernel
    pub(crate) fn dispatch<FS: Filesystem>(&self, se: &mut Session<FS>) {
        debug!("{}", self.request);
        let res = match self.dispatch_req(se) {
            Ok(Some(resp)) => resp,
            Ok(None) => return,
            Err(errno) => Response::new_error(errno),
        };
        self.reply::<ReplyRaw>().send_ll(&res);
    }

    fn dispatch_req<FS: Filesystem>(
        &self,
        se: &mut Session<FS>,
    ) -> Result<Option<Response<'_>>, Errno> {
        let op = self.request.operation().map_err(|_| Errno::ENOSYS)?;
        // Implement allow_root & access check for auto_unmount
        if (se.allowed == SessionACL::RootAndOwner
            && self.request.uid() != se.session_owner
            && !self.request.uid().is_root())
            || (se.allowed == SessionACL::Owner && self.request.uid() != se.session_owner)
        {
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
                    ll::Operation::ReadDirPlus(_) => {}
                    _ => {
                        return Err(Errno::EACCES);
                    }
                }
            }
        }
        match op {
            // Filesystem initialization - should not happen after handshake completed
            ll::Operation::Init(_) => {
                error!("Unexpected FUSE_INIT after handshake completed");
                return Err(Errno::EIO);
            }
            // Filesystem destroyed
            ll::Operation::Destroy(x) => {
                se.filesystem.destroy();
                se.destroyed = true;
                return Ok(Some(x.reply()));
            }
            // Any operation is invalid after destroy
            _ if se.destroyed => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                return Err(Errno::EIO);
            }

            ll::Operation::Interrupt(_) => {
                // TODO: handle FUSE_INTERRUPT
                return Err(Errno::ENOSYS);
            }

            ll::Operation::Lookup(x) => {
                se.filesystem.lookup(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Forget(x) => {
                se.filesystem
                    .forget(self.request_header(), self.request.nodeid(), x.nlookup()); // no reply
            }
            ll::Operation::GetAttr(_attr) => {
                se.filesystem.getattr(
                    self.request_header(),
                    self.request.nodeid(),
                    _attr.file_handle(),
                    self.reply(),
                );
            }
            ll::Operation::SetAttr(x) => {
                se.filesystem.setattr(
                    self.request_header(),
                    self.request.nodeid(),
                    x.mode(),
                    x.uid(),
                    x.gid(),
                    x.size(),
                    x.atime(),
                    x.mtime(),
                    x.ctime(),
                    x.file_handle(),
                    x.crtime(),
                    x.chgtime(),
                    x.bkuptime(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::ReadLink(_) => {
                se.filesystem
                    .readlink(self.request_header(), self.request.nodeid(), self.reply());
            }
            ll::Operation::MkNod(x) => {
                se.filesystem.mknod(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.rdev(),
                    self.reply(),
                );
            }
            ll::Operation::MkDir(x) => {
                se.filesystem.mkdir(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    self.reply(),
                );
            }
            ll::Operation::Unlink(x) => {
                se.filesystem.unlink(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::RmDir(x) => {
                se.filesystem.rmdir(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name().as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::SymLink(x) => {
                se.filesystem.symlink(
                    self.request_header(),
                    self.request.nodeid(),
                    x.link_name().as_ref(),
                    Path::new(x.target()),
                    self.reply(),
                );
            }
            ll::Operation::Rename(x) => {
                se.filesystem.rename(
                    self.request_header(),
                    self.request.nodeid(),
                    x.src().name.as_ref(),
                    x.dest().dir,
                    x.dest().name.as_ref(),
                    RenameFlags::empty(),
                    self.reply(),
                );
            }
            ll::Operation::Link(x) => {
                se.filesystem.link(
                    self.request_header(),
                    x.inode_no(),
                    self.request.nodeid(),
                    x.dest().name.as_ref(),
                    self.reply(),
                );
            }
            ll::Operation::Open(x) => {
                se.filesystem.open(
                    self.request_header(),
                    self.request.nodeid(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::Read(x) => {
                se.filesystem.read(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.offset()?,
                    x.size(),
                    x.flags(),
                    x.lock_owner(),
                    self.reply(),
                );
            }
            ll::Operation::Write(x) => {
                se.filesystem.write(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.offset(),
                    x.data(),
                    x.write_flags(),
                    x.flags(),
                    x.lock_owner(),
                    self.reply(),
                );
            }
            ll::Operation::Flush(x) => {
                se.filesystem.flush(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.lock_owner(),
                    self.reply(),
                );
            }
            ll::Operation::Release(x) => {
                se.filesystem.release(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.flags(),
                    x.lock_owner(),
                    x.flush(),
                    self.reply(),
                );
            }
            ll::Operation::FSync(x) => {
                se.filesystem.fsync(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::OpenDir(x) => {
                se.filesystem.opendir(
                    self.request_header(),
                    self.request.nodeid(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::ReadDir(x) => {
                se.filesystem.readdir(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.offset(),
                    ReplyDirectory::new(
                        self.request.unique(),
                        ReplySender::Channel(self.ch.clone()),
                        x.size() as usize,
                    ),
                );
            }
            ll::Operation::ReleaseDir(x) => {
                se.filesystem.releasedir(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::FSyncDir(x) => {
                se.filesystem.fsyncdir(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::StatFs(_) => {
                se.filesystem
                    .statfs(self.request_header(), self.request.nodeid(), self.reply());
            }
            ll::Operation::SetXAttr(x) => {
                se.filesystem.setxattr(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name(),
                    x.value(),
                    x.flags(),
                    x.position(),
                    self.reply(),
                );
            }
            ll::Operation::GetXAttr(x) => {
                se.filesystem.getxattr(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name(),
                    x.size_u32(),
                    self.reply(),
                );
            }
            ll::Operation::ListXAttr(x) => {
                se.filesystem.listxattr(
                    self.request_header(),
                    self.request.nodeid(),
                    x.size(),
                    self.reply(),
                );
            }
            ll::Operation::RemoveXAttr(x) => {
                se.filesystem.removexattr(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name(),
                    self.reply(),
                );
            }
            ll::Operation::Access(x) => {
                se.filesystem.access(
                    self.request_header(),
                    self.request.nodeid(),
                    x.mask(),
                    self.reply(),
                );
            }
            ll::Operation::Create(x) => {
                se.filesystem.create(
                    self.request_header(),
                    self.request.nodeid(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::GetLk(x) => {
                se.filesystem.getlk(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.lock_owner(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    self.reply(),
                );
            }
            ll::Operation::SetLk(x) => {
                se.filesystem.setlk(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.lock_owner(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    false,
                    self.reply(),
                );
            }
            ll::Operation::SetLkW(x) => {
                se.filesystem.setlk(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.lock_owner(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    true,
                    self.reply(),
                );
            }
            ll::Operation::BMap(x) => {
                se.filesystem.bmap(
                    self.request_header(),
                    self.request.nodeid(),
                    x.block_size(),
                    x.block(),
                    self.reply(),
                );
            }

            ll::Operation::IoCtl(x) => {
                if x.unrestricted() {
                    return Err(Errno::ENOSYS);
                }
                se.filesystem.ioctl(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.flags(),
                    x.command(),
                    x.in_data(),
                    x.out_size(),
                    self.reply(),
                );
            }
            ll::Operation::Poll(x) => {
                let ph = PollHandle::new(se.ch.sender(), x.kernel_handle());

                se.filesystem.poll(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
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
                se.filesystem.batch_forget(self.request_header(), x.nodes()); // no reply
            }
            ll::Operation::FAllocate(x) => {
                se.filesystem.fallocate(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.offset(),
                    x.len(),
                    x.mode(),
                    self.reply(),
                );
            }
            ll::Operation::ReadDirPlus(x) => {
                se.filesystem.readdirplus(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.offset(),
                    ReplyDirectoryPlus::new(
                        self.request.unique(),
                        ReplySender::Channel(self.ch.clone()),
                        x.size() as usize,
                    ),
                );
            }
            ll::Operation::Rename2(x) => {
                se.filesystem.rename(
                    self.request_header(),
                    x.from().dir,
                    x.from().name.as_ref(),
                    x.to().dir,
                    x.to().name.as_ref(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::Lseek(x) => {
                se.filesystem.lseek(
                    self.request_header(),
                    self.request.nodeid(),
                    x.file_handle(),
                    x.offset(),
                    x.whence(),
                    self.reply(),
                );
            }
            ll::Operation::CopyFileRange(x) => {
                let (i, o) = (x.src(), x.dest());
                se.filesystem.copy_file_range(
                    self.request_header(),
                    i.inode,
                    i.file_handle,
                    i.offset,
                    o.inode,
                    o.file_handle,
                    o.offset,
                    x.len(),
                    x.flags(),
                    self.reply(),
                );
            }
            #[cfg(target_os = "macos")]
            ll::Operation::SetVolName(x) => {
                se.filesystem
                    .setvolname(self.request_header(), x.name(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(x) => {
                se.filesystem
                    .getxtimes(self.request_header(), x.nodeid(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::Exchange(x) => {
                se.filesystem.exchange(
                    self.request_header(),
                    x.from().dir,
                    x.from().name.as_ref(),
                    x.to().dir,
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
        Reply::new(self.request.unique(), ReplySender::Channel(self.ch.clone()))
    }

    /// Returns a Request reference for this request
    #[inline]
    fn request_header(&self) -> &Request {
        Request::ref_cast(self.request.header())
    }
}
