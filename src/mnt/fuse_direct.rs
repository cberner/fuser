use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;

use nix::fcntl::OFlag;
use nix::fcntl::open;
use nix::sys::resource::Resource;
use nix::sys::resource::getrlimit;
use nix::sys::signal::SigSet;
use nix::sys::signal::SigmaskHow;
use nix::sys::signal::sigprocmask;
use nix::sys::stat::Mode;
use nix::unistd::ForkResult;
use nix::unistd::Uid;
use nix::unistd::close;
use nix::unistd::dup2_stderr;
use nix::unistd::dup2_stdin;
use nix::unistd::dup2_stdout;
use nix::unistd::fork;
use nix::unistd::setsid;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::mount_options::MountOption;
use crate::mnt::mount_options::MountOptionGroup;
use crate::mnt::mount_options::option_group;
use crate::mnt::mount_options::option_to_flag;
use crate::mnt::mount_options::option_to_string;

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

        let mut fsname: Option<&str> = None;
        let mut subtype: Option<&str> = None;
        let mut auto_unmount = false;

        #[cfg(target_os = "linux")]
        let mut flags = nix::mount::MsFlags::empty();
        #[cfg(any(
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "macos",
        ))]
        let mut flags = nix::mount::MntFlags::empty();

        #[cfg(not(target_os = "freebsd"))]
        if !uid.is_root() || !options.contains(&MountOption::Dev) {
            // Default to nodev
            #[cfg(target_os = "linux")]
            {
                flags |= nix::mount::MsFlags::MS_NODEV;
            }
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "macos",
            ))]
            {
                flags |= nix::mount::MntFlags::MNT_NODEV;
            }
        }

        if !uid.is_root() || !options.contains(&MountOption::Suid) {
            // default to nosuid
            #[cfg(target_os = "linux")]
            {
                flags |= nix::mount::MsFlags::MS_NOSUID;
            }
            #[cfg(any(
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "macos",
            ))]
            {
                flags |= nix::mount::MntFlags::MNT_NOSUID;
            }
        }

        let mut opts = Vec::new();
        for opt in options {
            match option_group(opt) {
                MountOptionGroup::KernelFlag => flags |= option_to_flag(opt)?,
                MountOptionGroup::KernelOption => write!(opts, "{},", option_to_string(opt))?,
                MountOptionGroup::Fusermount => match opt {
                    MountOption::FSName(val) => fsname = Some(val),
                    MountOption::Subtype(val) => subtype = Some(val),
                    MountOption::AutoUnmount => auto_unmount = true,
                    _ => {}
                },
            }
        }

        Self::do_mount(&mountpoint, fsname, subtype, flags, options, acl, dev_fd)?;

        let mut mnt = MountImpl {
            mountpoint,
            auto_unmount_socket: None,
        };

        if auto_unmount {
            mnt.setup_auto_unmount()?;
        }

        Ok((dev, mnt))
    }

    #[cfg(target_os = "macos")]
    fn do_mount(
        _mountpoint: &Path,
        _fsname: Option<&str>,
        _subtype: Option<&str>,
        _flags: nix::mount::MsFlags,
        _options: &[MountOption],
        _acl: SessionACL,
        _dev_fd: RawFd,
    ) -> io::Result<()> {
        // macos-no-mount - Don't actually mount
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn do_mount(
        mountpoint: &Path,
        fsname: Option<&str>,
        subtype: Option<&str>,
        flags: nix::mount::MsFlags,
        options: &[MountOption],
        acl: SessionACL,
        dev_fd: RawFd,
    ) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let mut opts = Vec::new();
        for opt in options {
            if option_group(opt) == MountOptionGroup::KernelOption {
                write!(opts, "{},", option_to_string(opt))?;
            }
        }

        if let Some(opt) = acl.to_mount_option() {
            write!(opts, "{opt},")?;
        }

        let root_mode = mountpoint
            .metadata()
            .map(|meta| meta.mode() & nix::sys::stat::SFlag::S_IFMT.bits())?;

        let old_len = opts.len();
        write!(
            opts,
            "fd={},rootmode={:o},user_id={},group_id={}",
            dev_fd,
            root_mode,
            Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )?;

        let mut ty = subtype.map_or("fuse".into(), |subtype| format!("fuse.{subtype}"));

        let mut source = if let Some(fsname) = fsname {
            fsname
        } else if let Some(subtype) = subtype {
            subtype
        } else {
            DEV_FUSE
        };

        let pagesize = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)?
            .map_or(usize::MAX, |ps| ps.try_into().unwrap_or(usize::MAX))
            - 1;

        if opts.len() > pagesize {
            log::error!(
                "mount options too long: '{}'",
                String::from_utf8_lossy(&opts)
            );
            return Err(nix::Error::EINVAL.into());
        }

        let mut res = nix::mount::mount(
            Some(source),
            mountpoint,
            Some(ty.as_str()),
            flags,
            Some(opts.as_slice()),
        );
        let source_tmp;
        if let Err(nix::Error::ENODEV) = &res {
            if let Some(subtype) = subtype {
                ty = "fuse".into();
                if let Some(fsname) = fsname {
                    source_tmp = format!("{subtype}#{fsname}");
                    source = source_tmp.as_str();
                } else {
                    source = ty.as_str();
                }

                res = nix::mount::mount(
                    Some(source),
                    mountpoint,
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
                Uid::current().as_raw(),
            )?;

            res = nix::mount::mount(
                Some(source),
                mountpoint,
                Some(ty.as_str()),
                flags,
                Some(opts.as_slice()),
            );
        }
        res.inspect_err(|err| log::error!("mount failed: {err}"))?;

        Ok(())
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    fn do_mount(
        mountpoint: &Path,
        fsname: Option<&str>,
        subtype: Option<&str>,
        flags: nix::mount::MntFlags,
        options: &[MountOption],
        acl: SessionACL,
        dev_fd: RawFd,
    ) -> io::Result<()> {
        let mut nmount = nix::mount::Nmount::new();

        if let Some(fsname) = fsname {
            nmount.str_opt_owned("fsname=", fsname);
        }

        if let Some(subtype) = subtype {
            nmount.str_opt_owned("subtype=", subtype);
        }

        if !matches!(acl, SessionACL::Owner) {
            nmount.str_opt_owned("allow_other", "");
        }

        for opt in options {
            if option_group(opt) == MountOptionGroup::KernelOption {
                nmount.str_opt_owned(option_to_string(opt).as_str(), "");
            }
        }

        nmount
            .str_opt(c"fstype", c"fusefs")
            .str_opt_owned("fspath", mountpoint)
            .str_opt(c"from", c"/dev/fuse")
            .str_opt_owned("fd", dev_fd.to_string().as_str())
            .nmount(flags)?;

        Ok(())
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        self.do_unmount(true)
    }

    #[cfg(target_os = "linux")]
    fn do_unmount(&mut self, lazy: bool) -> io::Result<()> {
        let flags = if lazy {
            nix::mount::MntFlags::MNT_DETACH
        } else {
            nix::mount::MntFlags::empty()
        };
        nix::mount::umount2(&self.mountpoint, flags)?;
        Ok(())
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "macos",
    ))]
    fn do_unmount(&mut self, lazy: bool) -> io::Result<()> {
        let flags = if lazy {
            nix::mount::MntFlags::MNT_FORCE
        } else {
            nix::mount::MntFlags::empty()
        };
        nix::mount::unmount(&self.mountpoint, flags)?;
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
        let etc_mtab = Path::new("/etc/mtab");
        let proc_mounts = Path::new("/proc/mounts");

        let mtab_path = if etc_mtab.try_exists()? {
            etc_mtab
        } else if proc_mounts.try_exists()? {
            proc_mounts
        } else {
            return Err(io::ErrorKind::NotFound.into());
        };

        let mut mtab = io::BufReader::new(File::open(mtab_path)?);
        let mut line = Vec::new();
        loop {
            line.clear();
            if mtab.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            let line = line.as_slice();

            let Some(fs_name_len) = line.iter().position(u8::is_ascii_whitespace) else {
                continue;
            };
            let line = &line[fs_name_len..];

            let Some(path_start) = line.iter().position(|b| !b.is_ascii_whitespace()) else {
                continue;
            };
            let line = &line[path_start..];
            let Some(path_len) = line.iter().position(u8::is_ascii_whitespace) else {
                continue;
            };
            let path = &line[..path_len];
            let line = &line[path_len..];

            let Some(fstype_start) = line.iter().position(|b| !b.is_ascii_whitespace()) else {
                continue;
            };
            let line = &line[fstype_start..];
            let Some(fstype_len) = line.iter().position(u8::is_ascii_whitespace) else {
                continue;
            };
            let fstype = &line[..fstype_len];

            let Some(path) = decode_mtab_str(path) else {
                continue;
            };
            if path != self.mountpoint.as_os_str()
                || !(fstype == b"fuse"
                    || fstype == b"fuseblk"
                    || fstype.starts_with(b"fuse.")
                    || fstype.starts_with(b"fuseblk."))
            {
                continue;
            }

            return Ok(true);
        }

        Ok(false)
    }
}

fn decode_mtab_str(mut s: &[u8]) -> Option<OsString> {
    let mut out = Vec::with_capacity(s.len());
    loop {
        let Some(next_escape) = s.iter().position(|b| *b == b'\\') else {
            out.extend_from_slice(s);
            break;
        };

        out.extend_from_slice(&s[..next_escape]);
        s = &s[(next_escape + 1)..];

        if s.len() < 3 {
            return None;
        }

        let byte = (oct_digit(s[0])? << 6) | (oct_digit(s[1])? << 3) | oct_digit(s[2])?;

        out.push(byte);

        s = &s[3..];
    }

    Some(OsString::from_vec(out))
}

fn oct_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'7' => Some(digit - b'0'),
        _ => None,
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
