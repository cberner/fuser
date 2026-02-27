// This example requires fuse 7.40 or later. Run with:
//
//   cargo run --example passthrough_fork /tmp/foobar

mod common;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use clap::Parser;
use fuser::BackingId;
use fuser::Errno;
use fuser::FileAttr;
use fuser::FileHandle;
use fuser::FileType;
use fuser::Filesystem;
use fuser::FopenFlags;
use fuser::INodeNo;
use fuser::InitFlags;
use fuser::KernelConfig;
use fuser::LockOwner;
use fuser::MountOption;
use fuser::OpenFlags;
use fuser::ReplyAttr;
use fuser::ReplyDirectory;
use fuser::ReplyEmpty;
use fuser::ReplyEntry;
use fuser::ReplyOpen;
use fuser::Request;
use nix::sys::socket;
use nix::sys::socket::MsgFlags;
use parking_lot::Mutex;

#[derive(Parser)]
#[command(version)]
struct Args {
    #[clap(flatten)]
    common_args: CommonArgs,
}

const TTL: Duration = Duration::from_secs(1); // 1 second

use crate::common::args::CommonArgs;

// See [./passthrough.rs]
#[derive(Debug, Default)]
struct BackingCache {
    by_handle: HashMap<u64, Arc<BackingId>>,
    by_inode: HashMap<INodeNo, Weak<BackingId>>,
    next_fh: u64,
}

impl BackingCache {
    fn next_fh(&mut self) -> u64 {
        self.next_fh += 1;
        self.next_fh
    }

    fn get_or(
        &mut self,
        ino: INodeNo,
        callback: impl Fn() -> std::io::Result<BackingId>,
    ) -> std::io::Result<(u64, Arc<BackingId>)> {
        let fh = self.next_fh();

        let id = if let Some(id) = self.by_inode.get(&ino).and_then(Weak::upgrade) {
            eprintln!("HIT! reusing {id:?}");
            id
        } else {
            let id = Arc::new(callback()?);
            self.by_inode.insert(ino, Arc::downgrade(&id));
            eprintln!("MISS! new {id:?}");
            id
        };

        self.by_handle.insert(fh, Arc::clone(&id));
        Ok((fh, id))
    }

    fn put(&mut self, fh: u64) {
        eprintln!("Put fh {fh}");
        match self.by_handle.remove(&fh) {
            None => eprintln!("ERROR: Put fh {fh} but it wasn't found in cache!!\n"),
            Some(id) => eprintln!("Put fh {fh}, was {id:?}\n"),
        }
    }
}

#[derive(Debug)]
struct ForkPassthroughFs {
    root_attr: FileAttr,
    passthrough_file_attr: FileAttr,
    socket: UnixDatagram,
    backing_cache: Mutex<BackingCache>,
}

impl ForkPassthroughFs {
    fn new(socket: UnixDatagram) -> Self {
        let uid = nix::unistd::getuid().into();
        let gid = nix::unistd::getgid().into();

        let root_attr = FileAttr {
            ino: INodeNo::ROOT,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH, // 1970-01-01 00:00:00
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            flags: 0,
            blksize: 512,
        };

        let passthrough_file_attr = FileAttr {
            ino: INodeNo(2),
            size: 123_456,
            blocks: 1,
            atime: UNIX_EPOCH, // 1970-01-01 00:00:00
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 333,
            gid: 333,
            rdev: 0,
            flags: 0,
            blksize: 512,
        };

        Self {
            root_attr,
            passthrough_file_attr,
            socket,
            backing_cache: Mutex::default(),
        }
    }
}

impl Filesystem for ForkPassthroughFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        config
            .add_capabilities(InitFlags::FUSE_PASSTHROUGH)
            .unwrap();
        config.set_max_stack_depth(2).unwrap();
        Ok(())
    }

    fn destroy(&mut self) {
        // Tell the parent process to shut down
        self.socket.send(&[]).unwrap();
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == INodeNo::ROOT && name.to_str() == Some("passthrough") {
            reply.entry(&TTL, &self.passthrough_file_attr, fuser::Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino.0 {
            1 => reply.attr(&TTL, &self.root_attr),
            2 => reply.attr(&TTL, &self.passthrough_file_attr),
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if ino != INodeNo(2) {
            reply.error(Errno::ENOENT);
            return;
        }

        let (fh, id) = self
            .backing_cache
            .lock()
            .get_or(ino, || {
                // Ask the parent process to open a backing ID for us (concurrency is left as an exercise for the reader)
                const FILE: &str = "/etc/profile";
                eprintln!("Asking server to open backing file for {FILE:?}");

                let mut buf = [0u8; 4];
                self.socket.send(FILE.as_bytes())?;
                self.socket.recv(&mut buf)?;
                Ok(unsafe { reply.wrap_backing(u32::from_ne_bytes(buf)) })
            })
            .unwrap();

        eprintln!("  -> opened_passthrough({fh:?}, 0, {id:?});\n");
        reply.opened_passthrough(FileHandle(fh), FopenFlags::empty(), &id);
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.backing_cache.lock().put(fh.into());
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "passthrough"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(INodeNo(entry.0), (i + 1) as u64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    // Fork and handle opening backing IDs in the parent process
    // Do this early since forking isn't guaranteed to be a safe operation once e.g. libraries get involved
    // You may also choose to use `std::process::Command` / etc instead
    let (parent_sock, child_sock) = UnixDatagram::pair().unwrap();
    match unsafe { nix::unistd::fork().unwrap() } {
        nix::unistd::ForkResult::Parent { .. } => {
            drop(child_sock);
            backing_id_server(parent_sock);
            return;
        }
        nix::unistd::ForkResult::Child => {
            drop(parent_sock);
        }
    }

    // You may wish to drop privileges (i.e. CAP_SYS_ADMIN / root) here

    // Mount the FS as usual
    let args = Args::parse();
    env_logger::init();

    let mut cfg = args.common_args.config();
    cfg.mount_options
        .extend([MountOption::FSName("passthrough".to_string())]);
    let fs = ForkPassthroughFs::new(child_sock.try_clone().unwrap());
    let session = fuser::Session::new(fs, &args.common_args.mount_point, &cfg).unwrap();

    // Send the FUSE FD to the parent process so it may open backing files
    let fds = [session.as_fd().as_raw_fd()];

    socket::sendmsg::<()>(
        child_sock.as_raw_fd(),
        &[],
        &[socket::ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .unwrap();

    // Run the FS
    session.run().unwrap();
}

fn backing_id_server(socket: UnixDatagram) {
    let mut buf = [0u8; 1024];

    // Receive the FUSE FD over the Unix socket
    let msg = socket::recvmsg::<()>(
        socket.as_fd().as_raw_fd(),
        &mut [],
        Some(&mut buf),
        MsgFlags::empty(),
    )
    .unwrap();

    let fuse_fd = 'fd: {
        for cmsg in msg.cmsgs().unwrap() {
            if let socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                let fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
                break 'fd fd;
            }
        }
        unreachable!();
    };

    // Handle backing ID requests (in real world scenarios, you may wish to perform input validation / etc here)
    loop {
        let sz = socket.recv(&mut buf).unwrap();
        if sz == 0 {
            return;
        }

        let path = OsStr::from_bytes(&buf[..sz]);
        eprintln!("[SERVER] opening backing file for {path:?}");

        let id = BackingId::create_raw(&fuse_fd, File::open(path).unwrap()).unwrap();
        socket.send(&u32::to_ne_bytes(id)).unwrap();
    }
}
