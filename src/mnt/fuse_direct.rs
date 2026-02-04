use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;

use log::error;
use log::warn;
use nix::fcntl::OFlag;
use nix::fcntl::open;
use nix::mount::MntFlags;
use nix::mount::MsFlags;
use nix::mount::mount;
use nix::mount::umount2;
use nix::sys::resource::Resource;
use nix::sys::resource::getrlimit;
use nix::sys::signal::SigSet;
use nix::sys::signal::SigmaskHow;
use nix::sys::signal::sigprocmask;
use nix::sys::stat::Mode;
use nix::sys::stat::SFlag;
use nix::unistd::ForkResult;
use nix::unistd::Gid;
use nix::unistd::SysconfVar;
use nix::unistd::Uid;
use nix::unistd::close;
use nix::unistd::dup2_stderr;
use nix::unistd::dup2_stdin;
use nix::unistd::dup2_stdout;
use nix::unistd::fork;
use nix::unistd::setsid;
use nix::unistd::sysconf;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::mount_options::MountOption;

const DEV_FUSE: &str = "/dev/fuse";

#[derive(Debug)]
pub(crate) struct MountImpl {
    mountpoint: PathBuf,
    auto_unmount_socket: Option<UnixStream>,
}

impl MountImpl {
    pub(crate) fn new(
        mountpoint: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, Self)> {
        let mountpoint = mountpoint.canonicalize()?;
        let dev = Arc::new(DevFuse(
            File::options().read(true).write(true).open(DEV_FUSE)?,
        ));
        let dev_fd = dev.as_raw_fd();

        let uid = Uid::current();
        let gid = Gid::current();

        let mut fsname: Option<&str> = None;
        let mut subtype: Option<&str> = None;
        let mut blkdev = false;
        let mut auto_unmount = false;
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;

        let mut opts = Vec::new();
        for opt in options {
            match opt {
                MountOption::FSName(val) => fsname = Some(val),
                MountOption::Subtype(val) => subtype = Some(val),
                MountOption::CUSTOM(val) if val == "blkdev" => {
                    if !uid.is_root() {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                    blkdev = true;
                }
                MountOption::AutoUnmount => auto_unmount = true,
                MountOption::RW => flags &= !MsFlags::MS_RDONLY,
                MountOption::RO => flags |= MsFlags::MS_RDONLY,
                MountOption::Suid if uid.is_root() => flags &= !MsFlags::MS_NOSUID,
                MountOption::Suid => warn!("unsafe mount option 'suid' ignored"),
                MountOption::NoSuid => flags |= MsFlags::MS_NOSUID,
                MountOption::Dev if uid.is_root() => flags &= !MsFlags::MS_NODEV,
                MountOption::Dev => warn!("unsafe mount option 'nodev' ignored"),
                MountOption::NoDev => flags |= MsFlags::MS_NODEV,
                MountOption::Exec => flags &= !MsFlags::MS_NOEXEC,
                MountOption::NoExec => flags |= MsFlags::MS_NOEXEC,
                MountOption::Async => flags &= !MsFlags::MS_SYNCHRONOUS,
                MountOption::Sync => flags |= MsFlags::MS_SYNCHRONOUS,
                MountOption::Atime => flags &= !MsFlags::MS_NOATIME,
                MountOption::NoAtime => flags |= !MsFlags::MS_NOATIME,
                MountOption::CUSTOM(val) if val == "diratime" => flags &= !MsFlags::MS_NODIRATIME,
                MountOption::CUSTOM(val) if val == "nodiratime" => flags |= MsFlags::MS_NODIRATIME,
                MountOption::CUSTOM(val) if val == "lazytime" => flags |= MsFlags::MS_LAZYTIME,
                MountOption::CUSTOM(val) if val == "nolazytime" => flags &= !MsFlags::MS_LAZYTIME,
                MountOption::CUSTOM(val) if val == "relatime" => flags |= MsFlags::MS_RELATIME,
                MountOption::CUSTOM(val) if val == "norelatime" => flags &= !MsFlags::MS_RELATIME,
                MountOption::CUSTOM(val) if val == "strictatime" => {
                    flags |= MsFlags::MS_STRICTATIME
                }
                MountOption::CUSTOM(val) if val == "nostrictatime" => {
                    flags &= !MsFlags::MS_STRICTATIME
                }
                MountOption::DirSync => flags |= MsFlags::MS_DIRSYNC,
                MountOption::DefaultPermissions => write!(opts, "default_permissions,")?,
                MountOption::CUSTOM(val)
                    if val.starts_with("max_read=") || val.starts_with("blksize=") =>
                {
                    write!(opts, "{val},")?
                }
                MountOption::CUSTOM(val) => {
                    error!("invalid mount option '{val}'");
                    return Err(nix::Error::EINVAL.into());
                }
            }
        }

        if let Some(opt) = acl.to_mount_option() {
            write!(opts, "{opt},")?;
        }

        let root_mode = mountpoint
            .metadata()
            .map(|meta| meta.mode() & SFlag::S_IFMT.bits())?;

        let old_len = opts.len();
        write!(
            opts,
            "fd={},rootmode={:o},user_id={},group_id={}",
            dev_fd,
            root_mode,
            uid.as_raw(),
            gid.as_raw(),
        )?;

        let mut ty = match (subtype, blkdev) {
            (None, false) => "fuse".into(),
            (None, true) => "fuseblk".into(),
            (Some(subtype), false) => format!("fuse.{subtype}"),
            (Some(subtype), true) => format!("fuseblk.{subtype}"),
        };

        let mut source = if let Some(fsname) = fsname {
            fsname
        } else if let Some(subtype) = subtype {
            subtype
        } else {
            DEV_FUSE
        };

        let pagesize = sysconf(SysconfVar::PAGE_SIZE)?
            .map_or(usize::MAX, |ps| ps.try_into().unwrap_or(usize::MAX))
            - 1;

        if opts.len() > pagesize {
            error!(
                "mount options too long: '{}'",
                String::from_utf8_lossy(&opts)
            );
            return Err(nix::Error::EINVAL.into());
        }

        let mut res = mount(
            Some(source),
            &mountpoint,
            Some(ty.as_str()),
            flags,
            Some(opts.as_slice()),
        );
        let source_tmp;
        if let Err(nix::Error::ENODEV) = &res {
            if let Some(subtype) = subtype {
                ty = (if blkdev { "fuseblk" } else { "fuse" }).into();
                source_tmp = match (fsname, blkdev) {
                    (Some(fsname), false) => format!("{subtype}#{fsname}"),
                    (Some(_), true) => source.into(),
                    _ => ty.clone(),
                };
                source = source_tmp.as_str();

                res = mount(
                    Some(source),
                    &mountpoint,
                    Some(ty.as_str()),
                    flags,
                    Some(opts.as_slice()),
                );
            }
        }
        if let Err(nix::Error::EINVAL) = &res {
            opts.truncate(old_len);

            write!(
                opts,
                "fd={},rootmode={:o},user_id={}",
                dev_fd,
                root_mode,
                uid.as_raw(),
            )?;

            res = mount(
                Some(source),
                &mountpoint,
                Some(ty.as_str()),
                flags,
                Some(opts.as_slice()),
            );
        }
        res.inspect_err(|err| error!("mount failed: {err}"))?;

        let mut mnt = MountImpl {
            mountpoint,
            auto_unmount_socket: None,
        };

        if auto_unmount {
            mnt.setup_auto_unmount()?;
        }

        Ok((dev, mnt))
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        self.do_unmount(true)
    }

    fn do_unmount(&mut self, lazy: bool) -> io::Result<()> {
        let flags = if lazy {
            MntFlags::MNT_DETACH
        } else {
            MntFlags::empty()
        };
        umount2(&self.mountpoint, flags)?;
        Ok(())
    }

    fn setup_auto_unmount(&mut self) -> io::Result<()> {
        let (tx, rx) = UnixStream::pair()?;

        if let ForkResult::Child = unsafe { fork() }? {
            exit(match self.do_auto_unmount(rx) {
                Ok(()) => 0,
                Err(err) => err.raw_os_error().unwrap_or(1),
            });
        }

        self.auto_unmount_socket = Some(tx);

        Ok(())
    }

    fn do_auto_unmount(&mut self, mut pipe: UnixStream) -> io::Result<()> {
        close_inherited_fds(pipe.as_raw_fd());
        let _ = setsid();
        let _ = sigprocmask(SigmaskHow::SIG_BLOCK, Some(&SigSet::empty()), None);

        let mut buf = [0u8; 16];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                _ => break,
            }
        }

        if self.should_auto_unmount()? {
            self.do_unmount(false)?;
        }

        Ok(())
    }

    fn should_auto_unmount(&self) -> io::Result<bool> {
        todo!()
    }
}

fn close_inherited_fds(pipe: RawFd) {
    let max_fds = getrlimit(Resource::RLIMIT_NOFILE).map_or(RawFd::MAX, |(soft, hard)| {
        Ord::min(soft, hard).try_into().unwrap_or(RawFd::MAX)
    });

    let _ = redirect_stdio();

    for fd in 3..=max_fds {
        if fd != pipe {
            let _ = close(fd);
        }
    }
}

fn redirect_stdio() -> io::Result<()> {
    let nullfd = open("/dev/null", OFlag::O_RDWR, Mode::empty())?;

    let _ = dup2_stdin(nullfd.as_fd());
    let _ = dup2_stdout(nullfd.as_fd());
    let _ = dup2_stderr(nullfd.as_fd());

    Ok(())
}
