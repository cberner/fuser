use clap::{Arg, ArgAction, Command, crate_version};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request, Session, SessionConfig, MtSession,
};
use libc::ENOENT;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(0); // 1 second

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

const HELLO_TXT_CONTENT: &str = "Hello World from Multi-threaded FUSE!\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 39,
    blocks: 1,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

struct HelloFS;

impl Filesystem for HelloFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &HELLO_TXT_ATTR, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        // Optional: Add artificial delay to simulate I/O work
        std::thread::sleep(Duration::from_micros(200));
        match ino {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
            _ => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == 2 {
            reply.data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != 1 {
            reply.error(ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    let matches = Command::new("hello_mt")
        .version(crate_version!())
        .author("Fuser Contributors")
        .about("Multi-threaded FUSE hello world example")
        .arg(
            Arg::new("MOUNT_POINT")
                .required(true)
                .index(1)
                .help("Act as a client, and mount FUSE at given path"),
        )
        .arg(
            Arg::new("auto_unmount")
                .long("auto_unmount")
                .action(ArgAction::SetTrue)
                .help("Automatically unmount on process exit"),
        )
        .arg(
            Arg::new("allow-root")
                .long("allow-root")
                .action(ArgAction::SetTrue)
                .help("Allow root user to access filesystem"),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .short('t')
                .value_name("NUM")
                .default_value("10")
                .help("Maximum number of worker threads (1 for single-threaded mode)"),
        )
        .arg(
            Arg::new("single-threaded")
                .long("single-threaded")
                .short('s')
                .action(ArgAction::SetTrue)
                .help("Run in single-threaded mode (equivalent to --threads=1)"),
        )
        .arg(
            Arg::new("clone-fd")
                .long("clone-fd")
                .action(ArgAction::SetTrue)
                .help("Clone /dev/fuse fd for each thread (Linux only)"),
        )
        .get_matches();

    env_logger::init();

    let mountpoint = matches.get_one::<String>("MOUNT_POINT").unwrap();

    // Determine number of threads
    let max_threads: usize = if matches.get_flag("single-threaded") {
        1
    } else {
        matches
            .get_one::<String>("threads")
            .unwrap()
            .parse()
            .expect("Invalid number of threads")
    };

    let clone_fd = matches.get_flag("clone-fd");

    let mut options = vec![MountOption::RO, MountOption::FSName("hello_mt".to_string())];
    if matches.get_flag("auto_unmount") {
        options.push(MountOption::AutoUnmount);
    }
    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    let mode = if max_threads == 1 {
        "single-threaded"
    } else {
        "multi-threaded"
    };

    log::info!("=== {} FUSE Filesystem ===", mode.to_uppercase());
    log::info!("Mountpoint: {}", mountpoint);
    log::info!("Mode: {}", mode);
    log::info!("Max threads: {}", max_threads);
    log::info!("Clone FD: {}", clone_fd);
    log::info!("");

    // Create a regular session
    let session = Session::new(HelloFS, mountpoint, &options)
        .expect("Failed to create session");

    // Configure multi-threading
    let config = SessionConfig::new()
        .max_threads(max_threads)
        .clone_fd(clone_fd);

    // Convert to multi-threaded session
    let mut mt_session = MtSession::from_session(session, config)
        .expect("Failed to create multi-threaded session");

    // Run the session loop
    log::info!("Starting {} session loop", mode);
    mt_session.run().expect("Session failed");
}
