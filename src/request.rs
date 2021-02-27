//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use crate::ll::fuse_abi as abi;
use libc::{EIO, ENOSYS, EPROTO};
use log::{debug, error, warn};
use std::convert::TryFrom;
#[cfg(feature = "abi-7-28")]
use std::convert::TryInto;
use std::path::Path;

use crate::channel::ChannelSender;
#[cfg(feature = "abi-7-21")]
use crate::reply::ReplyDirectoryPlus;
use crate::reply::{Reply, ReplyDirectory, ReplyEmpty, ReplyRaw};
use crate::session::Session;
use crate::Filesystem;
use crate::{ll, KernelConfig};

/// Request data structure
#[derive(Debug)]
pub struct Request<'a> {
    /// Channel sender for sending the reply
    ch: ChannelSender,
    /// Request raw data
    data: &'a [u8],
    /// Parsed request
    request: ll::Request<'a>,
}

impl<'a> Request<'a> {
    /// Create a new request from the given data
    pub fn new(ch: ChannelSender, data: &'a [u8]) -> Option<Request<'a>> {
        let request = match ll::Request::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                // FIXME: Reply with ENOSYS?
                error!("{}", err);
                return None;
            }
        };

        Some(Self { ch, data, request })
    }

    /// Dispatch request to the given filesystem.
    /// This calls the appropriate filesystem operation method for the
    /// request and sends back the returned reply to the kernel
    pub fn dispatch<FS: Filesystem>(&self, se: &mut Session<FS>) {
        debug!("{}", self.request);

        match self.request.operation() {
            // Filesystem initialization
            ll::Operation::Init(x) => {
                let reply: ReplyRaw<abi::fuse_init_out> = self.reply();
                // We don't support ABI versions before 7.6
                let v = x.version();
                if v < ll::Version(7, 6) {
                    error!("Unsupported FUSE ABI version {}", v);
                    reply.error(EPROTO);
                    return;
                }
                // Remember ABI version supported by kernel
                se.proto_major = v.major();
                se.proto_minor = v.minor();

                let mut config = KernelConfig::new(x.capabilities(), x.max_readahead());
                // Call filesystem init method and give it a chance to return an error
                let res = se.filesystem.init(self, &mut config);
                if let Err(err) = res {
                    reply.error(err);
                    return;
                }
                // Reply with our desired version and settings. If the kernel supports a
                // larger major version, it'll re-send a matching init message. If it
                // supports only lower major versions, we replied with an error above.
                let init = abi::fuse_init_out {
                    major: abi::FUSE_KERNEL_VERSION,
                    minor: abi::FUSE_KERNEL_MINOR_VERSION,
                    max_readahead: config.max_readahead,
                    flags: x.capabilities() & config.requested, // use requested features and reported as capable
                    #[cfg(not(feature = "abi-7-13"))]
                    unused: 0,
                    #[cfg(feature = "abi-7-13")]
                    max_background: config.max_background,
                    #[cfg(feature = "abi-7-13")]
                    congestion_threshold: config.congestion_threshold(),
                    max_write: config.max_write,
                    #[cfg(feature = "abi-7-23")]
                    time_gran: config.time_gran.as_nanos() as u32,
                    #[cfg(all(feature = "abi-7-23", not(feature = "abi-7-28")))]
                    reserved: [0; 9],
                    #[cfg(feature = "abi-7-28")]
                    max_pages: config.max_pages(),
                    #[cfg(feature = "abi-7-28")]
                    unused2: 0,
                    #[cfg(feature = "abi-7-28")]
                    reserved: [0; 8],
                };
                debug!(
                    "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                    init.major, init.minor, init.flags, init.max_readahead, init.max_write
                );
                se.initialized = true;
                reply.ok(&init);
            }
            // Any operation is invalid before initialization
            _ if !se.initialized => {
                warn!("Ignoring FUSE operation before init: {}", self.request);
                self.reply::<ReplyEmpty>().error(EIO);
            }
            // Filesystem destroyed
            ll::Operation::Destroy(_) => {
                se.filesystem.destroy(self);
                se.destroyed = true;
                self.reply::<ReplyEmpty>().ok();
            }
            // Any operation is invalid after destroy
            _ if se.destroyed => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                self.reply::<ReplyEmpty>().error(EIO);
            }

            ll::Operation::Interrupt(_) => {
                // TODO: handle FUSE_INTERRUPT
                self.reply::<ReplyEmpty>().error(ENOSYS);
            }

            ll::Operation::Lookup(x) => {
                se.filesystem
                    .lookup(self, self.request.nodeid().into(), &x.name(), self.reply());
            }
            ll::Operation::Forget(x) => {
                se.filesystem
                    .forget(self, self.request.nodeid().into(), x.nlookup()); // no reply
            }
            ll::Operation::GetAttr(_) => {
                se.filesystem
                    .getattr(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::SetAttr(x) => {
                se.filesystem.setattr(
                    self,
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
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::ReadLink(_) => {
                se.filesystem
                    .readlink(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::MkNod(x) => {
                se.filesystem.mknod(
                    self,
                    self.request.nodeid().into(),
                    &x.name(),
                    x.mode(),
                    x.umask(),
                    x.rdev(),
                    self.reply(),
                );
            }
            ll::Operation::MkDir(x) => {
                se.filesystem.mkdir(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.mode(),
                    x.umask(),
                    self.reply(),
                );
            }
            ll::Operation::Unlink(x) => {
                se.filesystem
                    .unlink(self, self.request.nodeid().into(), x.name(), self.reply());
            }
            ll::Operation::RmDir(x) => {
                se.filesystem
                    .rmdir(self, self.request.nodeid().into(), x.name(), self.reply());
            }
            ll::Operation::SymLink(x) => {
                se.filesystem.symlink(
                    self,
                    self.request.nodeid().into(),
                    x.target(),
                    &Path::new(x.link()),
                    self.reply(),
                );
            }
            ll::Operation::Rename(x) => {
                se.filesystem.rename(
                    self,
                    self.request.nodeid().into(),
                    x.from().name,
                    x.to().dir.into(),
                    x.to().name,
                    0,
                    self.reply(),
                );
            }
            ll::Operation::Link(x) => {
                se.filesystem.link(
                    self,
                    x.inode_no().into(),
                    self.request.nodeid().into(),
                    x.to().name,
                    self.reply(),
                );
            }
            ll::Operation::Open(x) => {
                se.filesystem
                    .open(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::Read(x) => {
                se.filesystem.read(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.size(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(),
                );
            }
            ll::Operation::Write(x) => {
                se.filesystem.write(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    x.data(),
                    x.write_flags(),
                    x.flags(),
                    x.lock_owner().map(|l| l.into()),
                    self.reply(),
                );
            }
            ll::Operation::Flush(x) => {
                se.filesystem.flush(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.lock_owner().into(),
                    self.reply(),
                );
            }
            ll::Operation::Release(x) => {
                se.filesystem.release(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    x.lock_owner().map(|x| x.into()),
                    x.flush(),
                    self.reply(),
                );
            }
            ll::Operation::FSync(x) => {
                se.filesystem.fsync(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::OpenDir(x) => {
                se.filesystem
                    .opendir(self, self.request.nodeid().into(), x.flags(), self.reply());
            }
            ll::Operation::ReadDir(x) => {
                se.filesystem.readdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectory::new(self.request.unique().into(), self.ch, x.size() as usize),
                );
            }
            ll::Operation::ReleaseDir(x) => {
                se.filesystem.releasedir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::FSyncDir(x) => {
                se.filesystem.fsyncdir(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.fdatasync(),
                    self.reply(),
                );
            }
            ll::Operation::StatFs(_) => {
                se.filesystem
                    .statfs(self, self.request.nodeid().into(), self.reply());
            }
            ll::Operation::SetXAttr(x) => {
                se.filesystem.setxattr(
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
                se.filesystem.getxattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.size(),
                    self.reply(),
                );
            }
            ll::Operation::ListXAttr(x) => {
                se.filesystem
                    .listxattr(self, self.request.nodeid().into(), x.size(), self.reply());
            }
            ll::Operation::RemoveXAttr(x) => {
                se.filesystem.removexattr(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    self.reply(),
                );
            }
            ll::Operation::Access(x) => {
                se.filesystem
                    .access(self, self.request.nodeid().into(), x.mask(), self.reply());
            }
            ll::Operation::Create(x) => {
                se.filesystem.create(
                    self,
                    self.request.nodeid().into(),
                    x.name(),
                    x.mode(),
                    x.umask(),
                    x.flags(),
                    self.reply(),
                );
            }
            ll::Operation::GetLk(x) => {
                se.filesystem.getlk(
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
                se.filesystem.setlk(
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
                se.filesystem.setlk(
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
                se.filesystem.bmap(
                    self,
                    self.request.nodeid().into(),
                    x.block_size(),
                    x.block(),
                    self.reply(),
                );
            }

            #[cfg(feature = "abi-7-11")]
            ll::Operation::IoCtl(x) => {
                if x.unrestricted() {
                    self.reply::<ReplyEmpty>().error(ENOSYS);
                } else {
                    se.filesystem.ioctl(
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
            }
            #[cfg(feature = "abi-7-11")]
            ll::Operation::Poll(_) => {
                // TODO: handle FUSE_POLL
                self.reply::<ReplyEmpty>().error(ENOSYS);
            }
            #[cfg(feature = "abi-7-15")]
            ll::Operation::NotifyReply(_) => {
                // TODO: handle FUSE_NOTIFY_REPLY
                self.reply::<ReplyEmpty>().error(ENOSYS);
            }
            #[cfg(feature = "abi-7-16")]
            ll::Operation::BatchForget(x) => {
                se.filesystem.batch_forget(self, x.nodes()); // no reply
            }
            #[cfg(feature = "abi-7-19")]
            ll::Operation::FAllocate(x) => {
                se.filesystem.fallocate(
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
                se.filesystem.readdirplus(
                    self,
                    self.request.nodeid().into(),
                    x.file_handle().into(),
                    x.offset(),
                    ReplyDirectoryPlus::new(
                        self.request.unique().into(),
                        self.ch,
                        x.size() as usize,
                    ),
                );
            }
            #[cfg(feature = "abi-7-23")]
            ll::Operation::Rename2(x) => {
                se.filesystem.rename(
                    self,
                    x.from().dir.into(),
                    x.from().name,
                    x.to().dir.into(),
                    x.to().name,
                    x.flags(),
                    self.reply(),
                );
            }
            #[cfg(feature = "abi-7-24")]
            ll::Operation::Lseek(x) => {
                se.filesystem.lseek(
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
                let (i, o) = (x.input(), x.output());
                se.filesystem.copy_file_range(
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
                se.filesystem.setvolname(self, x.name(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::GetXTimes(_) => {
                se.filesystem
                    .getxtimes(self, self.request.nodeid().into(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll::Operation::Exchange(x) => {
                se.filesystem.exchange(
                    self,
                    x.from().dir.into(),
                    x.from().name,
                    x.to().dir.into(),
                    x.to().name,
                    x.options(),
                    self.reply(),
                );
            }

            #[cfg(feature = "abi-7-12")]
            ll::Operation::CuseInit(_) => {
                // TODO: handle CUSE_INIT
                self.reply::<ReplyEmpty>().error(ENOSYS);
            }
        }
    }

    /// Create a reply object for this request that can be passed to the filesystem
    /// implementation and makes sure that a request is replied exactly once
    fn reply<T: Reply>(&self) -> T {
        Reply::new(self.request.unique().into(), self.ch)
    }

    /// Returns the unique identifier of this request
    #[inline]
    #[allow(dead_code)]
    pub fn unique(&self) -> u64 {
        self.request.unique().into()
    }

    /// Returns the uid of this request
    #[inline]
    #[allow(dead_code)]
    pub fn uid(&self) -> u32 {
        self.request.uid()
    }

    /// Returns the gid of this request
    #[inline]
    #[allow(dead_code)]
    pub fn gid(&self) -> u32 {
        self.request.gid()
    }

    /// Returns the pid of this request
    #[inline]
    #[allow(dead_code)]
    pub fn pid(&self) -> u32 {
        self.request.pid()
    }
}
