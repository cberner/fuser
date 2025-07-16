//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use crate::ll::{fuse_abi as abi, Errno};
use log::{debug, error, warn};
use std::convert::TryFrom;
#[cfg(feature = "abi-7-28")]
use std::convert::TryInto;

use crate::channel::ChannelSender;
use crate::ll::Request as _;
use crate::reply::{ReplyHandler};
use crate::session::{Session, SessionACL};
use crate::Filesystem;
#[cfg(feature = "abi-7-11")]
use crate::PollHandle;
use crate::{ll, KernelConfig, Forget};

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
    /// Request metadata
    meta: RequestMeta,
    /// Closure-like object to guarantee a response is sent
    replyhandler: ReplyHandler,
}

/// Request metadata structure
#[derive(Copy, Clone, Debug)]
pub struct RequestMeta {
    /// The unique identifier of this request
    pub unique: u64,
    /// The uid of this request
    pub uid: u32,
    /// The gid of this request
    pub gid: u32,
    /// The pid of this request
    pub pid: u32
}

impl<'a> Request<'a> {
    /// Create a new request from the given data
    pub(crate) fn new(ch: ChannelSender, data: &'a [u8]) -> Option<Request<'a>> {
        let request = match ll::AnyRequest::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                error!("{}", err);
                return None;
            }
        };

        let meta = RequestMeta {
            unique: request.unique().into(),
            uid: request.uid(),
            gid: request.gid(),
            pid: request.pid()
        };
        let replyhandler = ReplyHandler::new(request.unique().into(), ch.clone());
        Some(Self { ch, data, request, meta, replyhandler })
    }

    /// Dispatch request to the given filesystem.
    /// This calls the appropriate filesystem operation method for the
    /// request and sends back the returned reply to the kernel
    pub(crate) fn dispatch<FS: Filesystem>(self, se: &mut Session<FS>) {
        debug!("{}", self.request);
        let op_result = self.request.operation().map_err(|_| Errno::ENOSYS);

        if let Err(err) = op_result {
            self.replyhandler.error(err);
            return;
        }
        let op = op_result.unwrap();
        // Implement allow_root & access check for auto_unmount
        if (se.allowed == SessionACL::RootAndOwner
            && self.request.uid() != se.session_owner
            && self.request.uid() != 0)
            || (se.allowed == SessionACL::Owner && self.request.uid() != se.session_owner)
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
                        self.replyhandler.error(Errno::EACCES);
                    }
                }
            }
            #[cfg(all(feature = "abi-7-16", not(feature = "abi-7-21")))]
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
                        self.replyhandler.error(Errno::EACCES);
                    }
                }
            }
            #[cfg(not(feature = "abi-7-16"))]
            {
                match op {
                    // Only allow operations that the kernel may issue without a uid set
                    ll::Operation::Init(_)
                    | ll::Operation::Destroy(_)
                    | ll::Operation::Read(_)
                    | ll::Operation::ReadDir(_)
                    | ll::Operation::Forget(_)
                    | ll::Operation::Write(_)
                    | ll::Operation::FSync(_)
                    | ll::Operation::FSyncDir(_)
                    | ll::Operation::Release(_)
                    | ll::Operation::ReleaseDir(_) => {}
                    _ => {
                        self.replyhandler.error(Errno::EACCES);
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
                    error!("Unsupported FUSE ABI version {}", v);
                    self.replyhandler.error(Errno::EPROTO);
                    return;
                }
                // Remember ABI version supported by kernel
                se.proto_major = v.major();
                se.proto_minor = v.minor();

                let config = KernelConfig::new(x.capabilities(), x.max_readahead());
                // Call filesystem init method and give it a chance to 
                // propose a different config or return an error
                match se.filesystem.init(self.meta, config) {
                    Ok(config) => {
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
                        se.initialized = true;
                        self.replyhandler.config(x.capabilities(), config);
                    },
                    Err(errno) => {
                        // Filesystem refused the config.
                        self.replyhandler.error(errno);
                    }
                };
            }
            // Any operation is invalid before initialization
            _ if !se.initialized => {
                warn!("Ignoring FUSE operation before init: {}", self.request);
                self.replyhandler.error(Errno::EIO);
            }
            // Filesystem destroyed
            ll::Operation::Destroy(x) => {
                se.filesystem.destroy();
                se.destroyed = true;
                self.replyhandler.ok();
            }
            // Any operation is invalid after destroy
            _ if se.destroyed => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                self.replyhandler.error(Errno::EIO);
            }

            ll::Operation::Interrupt(_) => {
                // TODO: handle FUSE_INTERRUPT
                self.replyhandler.error(Errno::ENOSYS);
            }

            ll::Operation::Lookup(x) => {
                let response = se.filesystem.lookup(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                );
                match response {
                    Ok(entry) => {
                        self.replyhandler.entry(entry)
                    },
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Forget(x) => {
                let target = Forget {
                    ino: self.request.nodeid().into(),
                    nlookup: x.nlookup()
                };
                se.filesystem
                    .forget(self.meta, target); // no reply
            }
            ll::Operation::GetAttr(_attr) => {
                #[cfg(feature = "abi-7-9")]
                let response = se.filesystem.getattr(
                    self.meta,
                    self.request.nodeid().into(),
                    _attr.file_handle().map(|fh| fh.into())
                );
                // Pre-abi-7-9 does not support providing a file handle.
                #[cfg(not(feature = "abi-7-9"))]
                let response = se.filesystem.getattr(
                    self.meta,
                    self.request.nodeid().into(),
                    None,
                );
                match response {
                    Ok((attr,ttl))=> {
                        self.replyhandler.attr(attr, ttl)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::SetAttr(x) => {
                let response = se.filesystem.setattr(
                    self.meta,
                    self.request.nodeid().into(),
                    x.mode(),
                    x.uid(),
                    x.gid(),
                    x.size(),
                    x.atime(),
                    x.mtime(),
                    x.ctime(),
                    x.file_handle().map(|fh| fh.into()),
                    x.crtime(),
                    x.chgtime(),
                    x.bkuptime(),
                    x.flags()
                );
                match response {
                    Ok((attr, ttl))=> {
                        self.replyhandler.attr(attr, ttl)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::ReadLink(_) => {
                let response = se.filesystem.readlink(
                    self.meta,
                     self.request.nodeid().into()
                );
                match response {
                    Ok(data)=> {
                        self.replyhandler.data(data)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::MkNod(x) => {
                let response = se.filesystem.mknod(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.rdev()
                );
                match response {
                    Ok(entry)=> {
                        self.replyhandler.entry(entry)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::MkDir(x) => {
                let response = se.filesystem.mkdir(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask()
                );
                match response {
                    Ok(entry)=> {
                        self.replyhandler.entry(entry)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Unlink(x) => {
                let response = se.filesystem.unlink(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name().into()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::RmDir(x) => {
                let response = se.filesystem.rmdir(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::SymLink(x) => {
                let response = se.filesystem.symlink(
                    self.meta,
                    self.request.nodeid().into(),
                    x.link_name().as_ref(),
                    Path::new(x.target()),
                );
                match response {
                    Ok(entry)=> {
                        self.replyhandler.entry(entry)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Rename(x) => {
                let response = se.filesystem.rename(
                    self.meta,
                    self.request.nodeid().into(),
                    x.src().name.as_ref(),
                    x.dest().dir.into(),
                    x.dest().name.as_ref(),
                    0
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Link(x) => {
                let response = se.filesystem.link(
                    self.meta,
                    x.inode_no().into(),
                    self.request.nodeid().into(),
                    x.dest().name.as_ref(),
                );
                match response {
                    Ok(entry)=> {
                        self.replyhandler.entry(entry)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Open(x) => {
                let response = se.filesystem.open(
                    self.meta,
                    self.request.nodeid().into(), 
                    x.flags()
                );
                match response {
                    Ok(open)=> {
                        self.replyhandler.opened(open)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Read(x) => {
                let response = se.filesystem.read(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.size(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into())
                );
                match response {
                    Ok(data)=> {
                        self.replyhandler.data(data.as_ref())
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Write(x) => {
                let response = se.filesystem.write(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.data(),
                    x.write_flags(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into())
                );
                match response {
                    Ok(size)=> {
                        self.replyhandler.written(size)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Flush(x) => {
                let response = se.filesystem.flush(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Release(x) => {
                let response = se.filesystem.release(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.lock_owner().map(|x| x.into()),
                    x.flush()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::FSync(x) => {
                let response = se.filesystem.fsync(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::OpenDir(x) => {
                let response = se.filesystem.opendir(
                    self.meta,
                    self.request.nodeid().into(), 
                    x.flags()
                );
                match response {
                    Ok(open)=> {
                        self.replyhandler.opened(open)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::ReadDir(x) => {
                let response = se.filesystem.readdir(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                );
                match response {
                    Ok(entries_list_result)=> {
                        self.replyhandler.dir(
                        )
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::ReleaseDir(x) => {
                let response = se.filesystem.releasedir(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::FSyncDir(x) => {
                let response = se.filesystem.fsyncdir(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::StatFs(_) => {
                let response = se.filesystem.statfs(
                    self.meta,
                    self.request.nodeid().into()
                );
                match response {
                    Ok(statfs)=> {
                        self.replyhandler.statfs(statfs)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::SetXAttr(x) => {
                let response = se.filesystem.setxattr(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name(),
                    x.value(),
                    x.flags(),
                    x.position()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::GetXAttr(x) => {
                let response = se.filesystem.getxattr(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name(),
                    x.size_u32()
                );
                match response {
                    Ok(xattr)=> {
                        self.replyhandler.xattr(xattr)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::ListXAttr(x) => {
                let response = se.filesystem.listxattr(
                    self.meta,
                    self.request.nodeid().into(),
                    x.size()
                );
                match response {
                    Ok(xattr)=> {
                        self.replyhandler.xattr(xattr)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::RemoveXAttr(x) => {
                let response = se.filesystem.removexattr(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name(),
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Access(x) => {
                let response = se.filesystem.access(
                    self.meta,
                    self.request.nodeid().into(),
                    x.mask()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::Create(x) => {
                let response = se.filesystem.create(
                    self.meta,
                    self.request.nodeid().into(),
                    x.name().as_ref(),
                    x.mode(),
                    x.umask(),
                    x.flags()
                );
                match response {
                    Ok((entry, open))=> {
                        self.replyhandler.created(entry, open)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::GetLk(x) => {
                let response = se.filesystem.getlk(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid
                );
                match response {
                    Ok(lock)=> {
                        self.replyhandler.locked(lock)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::SetLk(x) => {
                let response = se.filesystem.setlk(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    false
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::SetLkW(x) => {
                let response = se.filesystem.setlk(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    x.lock().range.0,
                    x.lock().range.1,
                    x.lock().typ,
                    x.lock().pid,
                    true
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            ll::Operation::BMap(x) => {
                let response = se.filesystem.bmap(
                    self.meta,
                    self.request.nodeid().into(),
                    x.block_size(),
                    x.block()
                );
                match response {
                    Ok(block)=> {
                        self.replyhandler.bmap(block)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }

            #[cfg(feature = "abi-7-11")]
            ll::Operation::IoCtl(x) => {
                if x.unrestricted() {
                    self.replyhandler.error(Errno::ENOSYS);
                } else {
                    let response = se.filesystem.ioctl(
                        self.meta,
                        self.request.nodeid().into(),
                        x.file_handle().into(),
                        x.flags(),
                        x.command(),
                        x.in_data(),
                        x.out_size()
                    );
                    match response {
                        Ok(ioctl)=> {
                            self.replyhandler.ioctl(ioctl)
                        }
                        Err(err)=>{
                            self.replyhandler.error(err)
                        }
                    }
                }
            }
            #[cfg(feature = "abi-7-11")]
            ll::Operation::Poll(x) => {
                let ph = PollHandle::new(se.ch.sender(), x.kernel_handle());
                let response = se.filesystem.poll(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    ph,
                    x.events(),
                    x.flags()
                );
                match response {
                    Ok(revents)=> {
                        self.replyhandler.poll(revents)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
                // TODO: register the poll handler
                // TODO: receive poll data from the application
                // TODO: use the poll handler to send the data
            }
            #[cfg(feature = "abi-7-15")]
            ll::Operation::NotifyReply(_) => {
                // TODO: handle FUSE_NOTIFY_REPLY
                self.replyhandler.error(Errno::ENOSYS);
            }
            #[cfg(feature = "abi-7-16")]
            ll::Operation::BatchForget(x) => {
                se.filesystem.batch_forget(self.meta, x.into()); // no reply
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                let response = se.filesystem.fallocate(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.len(),
                    x.mode()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            #[cfg(feature = "abi-7-21")]
            ll::Operation::ReadDirPlus(x) => {
                let response = se.filesystem.readdirplus(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                );
                match response {
                    Ok(plus_entries_list_result)=> {
                        self.replyhandler.dirplus(
                        )
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(x) => {
                let response = se.filesystem.rename(
                    self.meta,
                    x.from().dir.into(),
                    x.from().name.as_ref(),
                    x.to().dir.into(),
                    x.to().name.as_ref(),
                    x.flags()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(x) => {
                let response = se.filesystem.lseek(
                    self.meta,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.whence()
                );
                match response {
                    Ok(offset)=> {
                        self.replyhandler.offset(offset)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            #[cfg(feature = "abi-7-28")]
            ll::Operation::CopyFileRange(x) => {
                let (i, o) = (x.src(), x.dest());
                let response = se.filesystem.copy_file_range(
                    self.meta,
                    i.inode.into(),
                    i.file_handle.into(),
                    i.offset,
                    o.inode.into(),
                    o.file_handle.into(),
                    o.offset,
                    x.len(),
                    x.flags().try_into().unwrap()
                );
                match response {
                    Ok(written)=> {
                        self.replyhandler.written(written)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            #[cfg(target_os = "macos")]
            ll::Operation::SetVolName(x) => {
                let response = se.filesystem.setvolname(
                    self.meta,
                    x.name()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(x) => {
                let response = se.filesystem.getxtimes(
                    self.meta,
                    x.nodeid().into()
                );
                match response {
                    Ok(xtimes)=> {
                        self.replyhandler.xtimes(xtimes)
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }

                }
            }
            #[cfg(target_os = "macos")]
            ll::Operation::Exchange(x) => {
                let response = se.filesystem.exchange(
                    self.meta,
                    x.from().dir.into(),
                    x.from().name.into(),
                    x.to().dir.into(),
                    x.to().name.into(),
                    x.options()
                );
                match response {
                    Ok(())=> {
                        self.replyhandler.ok()
                    }
                    Err(err)=>{
                        self.replyhandler.error(err)
                    }
                }
            }

            #[cfg(feature = "abi-7-12")]
            ll::Operation::CuseInit(_) => {
                // TODO: handle CUSE_INIT
                self.replyhandler.error(Errno::ENOSYS);
            }
        }
    }
}
