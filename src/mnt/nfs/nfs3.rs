//! The NFSv3 (RFC 1813) and MOUNT v3 procedures, answered with FUSE requests.
//!
//! A file handle is the FUSE node id and the server's key. Replies carry attributes where FUSE
//! handed them over anyway, and WRITE's and COMMIT's weak cache consistency data, by which the
//! client tells its own writes from another's. Elsewhere that data is left out, which the
//! client takes as a reason to fetch attributes again.

use std::io;
use std::io::Read;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use log::trace;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

use super::fuse::DirEntry;
use super::fuse::Fuse;
use super::fuse::READDIR_SIZE;
use super::fuse::S_IFDIR;
use super::fuse::S_IFMT;
use super::nfs4::Nfs4;
use super::xdr;
use super::xdr::Reader;
use super::xdr::Writer;
use crate::ll::flags::fattr_flags::FattrFlags;
use crate::ll::fuse_abi::fuse_attr;
use crate::ll::fuse_abi::fuse_entry_out;
use crate::ll::fuse_abi::fuse_link_in;
use crate::ll::fuse_abi::fuse_mkdir_in;
use crate::ll::fuse_abi::fuse_opcode;
use crate::ll::fuse_abi::fuse_rename_in;
use crate::ll::fuse_abi::fuse_setattr_in;

pub(crate) const NFS_PROGRAM: u32 = 100003;
pub(crate) const MOUNT_PROGRAM: u32 = 100005;
/// Of both programs
pub(crate) const VERSION: u32 = 3;
/// The largest read or write one NFS call may carry. Larger than one FUSE request may be:
/// calls are split to fit, so that clients are not held to a small FUSE `max_write`
pub(crate) const MAX_IO: u32 = 1024 * 1024;

const S_IFLNK: u32 = 0o120000;
const S_IFBLK: u32 = 0o060000;
const S_IFCHR: u32 = 0o020000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;

// nfsstat3
const NFS3_OK: u32 = 0;
const NFS3ERR_IO: u32 = 5;
const NFS3ERR_ROFS: u32 = 30;
const NFS3ERR_BADHANDLE: u32 = 10001;
const NFS3ERR_NOTSUPP: u32 = 10004;
const NFS3ERR_TOOSMALL: u32 = 10005;
const NFS3ERR_BADTYPE: u32 = 10007;

// ftype3
const NF3REG: u32 = 1;
const NF3DIR: u32 = 2;
const NF3BLK: u32 = 3;
const NF3CHR: u32 = 4;
const NF3LNK: u32 = 5;
const NF3SOCK: u32 = 6;
const NF3FIFO: u32 = 7;

// stable_how
const UNSTABLE: u32 = 0;
const FILE_SYNC: u32 = 2;
/// `createmode3`
const EXCLUSIVE: u32 = 2;

/// How many 4-byte words of "no data" follow the status of a failed call: absent attributes,
/// handles and weak cache consistency data. By procedure
const FAIL_WORDS: [usize; 22] = [
    0, // NULL
    0, // GETATTR
    2, // SETATTR: wcc_data
    1, // LOOKUP: dir_attributes
    1, // ACCESS
    1, // READLINK
    1, // READ
    2, // WRITE
    2, // CREATE: dir_wcc
    2, // MKDIR
    2, // SYMLINK
    2, // MKNOD
    2, // REMOVE
    2, // RMDIR
    4, // RENAME: fromdir_wcc, todir_wcc
    3, // LINK: file_attributes, linkdir_wcc
    1, // READDIR
    1, // READDIRPLUS
    1, // FSSTAT
    1, // FSINFO
    1, // PATHCONF
    2, // COMMIT
];

/// Why a call is answered with an RPC error rather than procedure results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    NoProcedure,
    Garbage,
}

/// How a procedure failed
enum Error {
    Garbage,
    Errno(i32),
    Status(u32),
}

impl From<xdr::Garbage> for Error {
    fn from(_: xdr::Garbage) -> Self {
        Error::Garbage
    }
}

impl From<i32> for Error {
    fn from(errno: i32) -> Self {
        Error::Errno(errno)
    }
}

type Result<T = ()> = std::result::Result<T, Error>;

/// Attributes a client asks to set
#[derive(Debug, Default)]
pub(super) struct Sattr {
    pub(super) mode: Option<u32>,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
    pub(super) size: Option<u64>,
    pub(super) atime: SetTime,
    pub(super) mtime: SetTime,
}

#[derive(Debug, Default)]
pub(super) enum SetTime {
    #[default]
    Keep,
    Now,
    At(u32, u32),
}

/// Answers NFS and MOUNT calls for one FUSE session
#[derive(Debug)]
pub(crate) struct Nfs {
    fuse: Fuse,
    read_only: bool,
    /// The path MNT answers: the filesystem's name and a secret made up for the server, which
    /// the mount table shows only once the mount is in use
    export: Vec<u8>,
    /// Write verifier: the same for as long as this server runs
    verifier: [u8; 8],
    /// Random, and part of every file handle, so that the handles cannot be made up
    key: [u8; 8],
    /// A request has used a handle: the mount this server is for is in use, and MNT hands out
    /// no more
    mounted: AtomicBool,
    v4: Nfs4,
    /// The mount is NFSv4's, not NFSv3's
    #[cfg_attr(not(any(fuser_mount_impl = "nfs", test)), allow(dead_code))]
    is_v4: bool,
}

impl Nfs {
    /// A server for a mount with NFSv3, or with `v4` NFSv4.1. The other version cannot then
    /// hand out file handles at all
    pub(crate) fn new(fuse: Fuse, read_only: bool, export: &str, v4: bool) -> io::Result<Self> {
        let mut random = [0; 24];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let verifier: [u8; 8] = random[..8].try_into().expect("8 bytes");
        let key: [u8; 8] = random[8..16].try_into().expect("8 bytes");
        let secret = random[16..].iter().fold(String::new(), |mut hex, b| {
            hex.push_str(&format!("{b:02x}"));
            hex
        });
        let name = if export.is_empty() {
            secret
        } else {
            format!("{export}.{secret}")
        };
        Ok(Self {
            v4: Nfs4::new(fuse.clone(), read_only, key, verifier, name.clone(), !v4),
            fuse,
            read_only,
            export: format!("/{name}").into_bytes(),
            verifier,
            key,
            mounted: AtomicBool::new(v4),
            is_v4: v4,
        })
    }

    /// The path `mount_nfs` mounts, for the version the server is for
    #[cfg_attr(not(any(fuser_mount_impl = "nfs", test)), allow(dead_code))]
    pub(crate) fn export_path(&self) -> String {
        if self.is_v4 {
            self.v4.export_path()
        } else {
            String::from_utf8_lossy(&self.export).into_owned()
        }
    }

    pub(crate) fn v4(&self) -> &Nfs4 {
        &self.v4
    }

    /// Runs MOUNT procedure `proc`, returning its encoded results
    pub(crate) fn mount(&self, proc: u32, args: &[u8]) -> std::result::Result<Vec<u8>, Refused> {
        let mut out = Vec::new();
        match proc {
            // NULL, UMNT, UMNTALL: nothing is kept per client
            0 | 3 | 4 => {}
            // MNT: the export's secret path mounts the root, until the mount is in use. Other
            // local users can reach this server too, but know no path to ask for before then,
            // and get nothing after. Some clients ask more than once, as libnfs does
            1 => {
                let path = Reader::new(args).opaque().map_err(|_| Refused::Garbage)?;
                if self.mounted.load(Ordering::SeqCst) || path != self.export.as_slice() {
                    // MNT3ERR_ACCES
                    out.put_u32(13);
                    return Ok(out);
                }
                out.put_u32(0);
                self.put_handle(&mut out, super::fuse::ROOT);
                // AUTH_UNIX only
                out.put_u32(1);
                out.put_u32(1);
            }
            // DUMP: no list of clients
            2 => out.put_bool(false),
            // EXPORT: none listed, as the path is the secret
            5 => out.put_bool(false),
            _ => return Err(Refused::NoProcedure),
        }
        Ok(out)
    }

    /// Runs NFS procedure `proc`, returning its encoded results
    pub(crate) fn nfs(&self, proc: u32, args: &[u8]) -> std::result::Result<Vec<u8>, Refused> {
        let Some(&fail_words) = FAIL_WORDS.get(proc as usize) else {
            return Err(Refused::NoProcedure);
        };
        if proc == 0 {
            return Ok(Vec::new());
        }
        let a = &mut Reader::new(args);
        let mut out = Vec::new();
        out.put_u32(NFS3_OK);
        let result = if self.read_only && matches!(proc, 2 | 7..=15) {
            Err(Error::Status(NFS3ERR_ROFS))
        } else {
            match proc {
                1 => self.getattr(a, &mut out),
                2 => self.setattr(a, &mut out),
                3 => self.lookup(a, &mut out),
                4 => self.access(a, &mut out),
                5 => self.readlink(a, &mut out),
                6 => self.read(a, &mut out),
                7 => self.write(a, &mut out),
                8 => self.create(a, &mut out),
                9 => self.mkdir(a, &mut out),
                10 => self.symlink(a, &mut out),
                11 => self.mknod(a, &mut out),
                12 => self.remove(a, &mut out, fuse_opcode::FUSE_UNLINK),
                13 => self.remove(a, &mut out, fuse_opcode::FUSE_RMDIR),
                14 => self.rename(a, &mut out),
                15 => self.link(a, &mut out),
                16 => self.readdir(a, &mut out, false),
                17 => self.readdir(a, &mut out, true),
                18 => self.fsstat(a, &mut out),
                19 => self.fsinfo(a, &mut out),
                20 => self.pathconf(a, &mut out),
                _ => self.commit(a, &mut out),
            }
        };
        let status = match result {
            Ok(()) => return Ok(out),
            Err(Error::Garbage) => return Err(Refused::Garbage),
            Err(Error::Errno(errno)) => nfsstat(errno),
            Err(Error::Status(status)) => status,
        };
        out.clear();
        out.put_u32(status);
        out.resize(4 + 4 * fail_words, 0);
        Ok(out)
    }

    /// Decodes a file handle: a node id, then this server's key
    fn handle(&self, a: &mut Reader<'_>) -> Result<u64> {
        let data = a.opaque()?;
        match (data.get(..8), data.get(8..)) {
            (Some(node), Some(key)) if key == self.key => {
                match u64::from_be_bytes(node.try_into().expect("8 bytes")) {
                    0 => Err(Error::Status(NFS3ERR_BADHANDLE)),
                    node => {
                        self.mounted.store(true, Ordering::SeqCst);
                        Ok(node)
                    }
                }
            }
            _ => Err(Error::Status(NFS3ERR_BADHANDLE)),
        }
    }

    /// What every file handle ends with, for tests to make handles of their own
    #[cfg(test)]
    pub(crate) fn handle_key(&self) -> [u8; 8] {
        self.key
    }

    fn put_handle(&self, out: &mut Vec<u8>, node: u64) {
        out.put_opaque(&[&node.to_be_bytes()[..], &self.key].concat());
    }

    fn getattr(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        put_fattr(out, &self.fuse.getattr(node)?);
        Ok(())
    }

    fn setattr(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        let attr = sattr(a)?;
        // sattrguard3: the ctime check is not made
        if a.bool()? {
            a.u64()?;
        }
        // wcc_data: no attributes from before
        out.put_bool(false);
        match setattr_in(&attr, false) {
            Some(arg) => put_post_op(out, Some(&self.fuse.setattr(node, &arg)?)),
            None => put_post_op(out, None),
        }
        Ok(())
    }

    fn lookup(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let dir = self.handle(a)?;
        let name = name_arg(a.opaque()?, Name::Lookup)?;
        let (node, attr) = if name == b"." || name == b".." {
            let node = self.fuse.resolve(dir, name)?;
            (node, self.fuse.getattr(node)?)
        } else {
            let entry = self.fuse.lookup(dir, name)?;
            (entry.nodeid, entry.attr)
        };
        self.put_handle(out, node);
        put_post_op(out, Some(&attr));
        // dir_attributes
        put_post_op(out, None);
        Ok(())
    }

    fn access(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        let access = a.u32()?;
        let granted = self.fuse.granted_access(node, access)?;
        put_post_op(out, None);
        out.put_u32(granted);
        Ok(())
    }

    fn readlink(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        let target = self.fuse.call(fuse_opcode::FUSE_READLINK, node, &[])?;
        put_post_op(out, None);
        out.put_opaque(&target);
        Ok(())
    }

    fn read(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        let offset = a.u64()?;
        let count = a.u32()?.min(MAX_IO);
        let (data, eof) = self.fuse.read(node, offset, count)?;
        put_post_op(out, None);
        out.put_u32(data.len() as u32);
        out.put_bool(eof);
        out.put_opaque(&data);
        Ok(())
    }

    fn write(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        let offset = a.u64()?;
        // count: the data says how much
        a.u32()?;
        let stable = a.u32()?;
        let data = a.opaque()?;
        trace!(
            "NFSv3 WRITE of {} bytes at {offset}, stable {stable}",
            data.len()
        );
        // The attributes around the write let the client tell its own change from another's,
        // without which it would drop what it has cached of the file
        let before = self.fuse.getattr(node).ok();
        self.fuse.write(node, offset, data)?;
        // Unstable writes reach the filesystem's fsync with the COMMIT that follows them
        let committed = if stable == UNSTABLE {
            UNSTABLE
        } else {
            self.fuse.fsync(node)?;
            FILE_SYNC
        };
        put_wcc(out, before.as_ref(), self.fuse.getattr(node).ok().as_ref());
        out.put_u32(data.len() as u32);
        out.put_u32(committed);
        out.put_fixed(&self.verifier);
        Ok(())
    }

    fn create(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let dir = self.handle(a)?;
        let name = name_arg(a.opaque()?, Name::Create)?;
        let how = a.u32()?;
        let attr = if how == EXCLUSIVE {
            // The verifier is not kept: a retransmitted exclusive create fails
            a.fixed(8)?;
            Sattr::default()
        } else {
            sattr(a)?
        };
        let entry = self
            .fuse
            .create(dir, name, attr.mode.unwrap_or(0o644), how != 0)?;
        self.created(out, entry, &attr)
    }

    fn mkdir(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let dir = self.handle(a)?;
        let name = name_arg(a.opaque()?, Name::Create)?;
        let attr = sattr(a)?;
        let arg = fuse_mkdir_in {
            mode: attr.mode.unwrap_or(0o755) & 0o7777,
            umask: 0,
        };
        let entry = self
            .fuse
            .make(fuse_opcode::FUSE_MKDIR, dir, &[arg.as_bytes(), name, b"\0"])?;
        self.created(out, entry, &attr)
    }

    fn symlink(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let dir = self.handle(a)?;
        let name = name_arg(a.opaque()?, Name::Create)?;
        // Its attributes are not set: a symlink's are not used
        sattr(a)?;
        let target = a.opaque()?;
        let entry = self.fuse.make(
            fuse_opcode::FUSE_SYMLINK,
            dir,
            &[name, b"\0", target, b"\0"],
        )?;
        self.created(out, entry, &Sattr::default())
    }

    fn mknod(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let dir = self.handle(a)?;
        let name = name_arg(a.opaque()?, Name::Create)?;
        let kind = match a.u32()? {
            NF3CHR => S_IFCHR,
            NF3BLK => S_IFBLK,
            NF3SOCK => S_IFSOCK,
            NF3FIFO => S_IFIFO,
            _ => return Err(Error::Status(NFS3ERR_BADTYPE)),
        };
        let attr = sattr(a)?;
        let rdev = if kind == S_IFCHR || kind == S_IFBLK {
            {
                // u32 on Linux, i32 on macOS
                let (major, minor) = (a.u32()?, a.u32()?);
                libc::makedev(major as _, minor as _) as u32
            }
        } else {
            0
        };
        let mode = kind | (attr.mode.unwrap_or(0o644) & 0o7777);
        let entry = self.fuse.mknod(dir, name, mode, rdev)?;
        self.created(out, entry, &attr)
    }

    /// Answers a call that made `entry`, after setting what else of `attr` there is to set
    fn created(&self, out: &mut Vec<u8>, entry: fuse_entry_out, attr: &Sattr) -> Result {
        let attr = match setattr_in(attr, true) {
            Some(arg) => self.fuse.setattr(entry.nodeid, &arg)?,
            None => entry.attr,
        };
        // post_op_fh3
        out.put_bool(true);
        self.put_handle(out, entry.nodeid);
        put_post_op(out, Some(&attr));
        put_no_wcc(out);
        Ok(())
    }

    fn remove(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, opcode: fuse_opcode) -> Result {
        let dir = self.handle(a)?;
        let name = name_arg(
            a.opaque()?,
            if matches!(opcode, fuse_opcode::FUSE_RMDIR) {
                Name::Rmdir
            } else {
                Name::Unlink
            },
        )?;
        self.fuse.call(opcode, dir, &[name, b"\0"])?;
        put_no_wcc(out);
        Ok(())
    }

    fn rename(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let from_dir = self.handle(a)?;
        let from = name_arg(a.opaque()?, Name::Rename)?;
        let to_dir = self.handle(a)?;
        let to = name_arg(a.opaque()?, Name::Rename)?;
        let arg = fuse_rename_in { newdir: to_dir };
        self.fuse.call(
            fuse_opcode::FUSE_RENAME,
            from_dir,
            &[arg.as_bytes(), from, b"\0", to, b"\0"],
        )?;
        if from_dir != to_dir {
            // If a directory moved, this records its new parent for ".."
            let _ = self.fuse.lookup(to_dir, to);
        }
        put_no_wcc(out);
        put_no_wcc(out);
        Ok(())
    }

    fn link(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        let dir = self.handle(a)?;
        let name = name_arg(a.opaque()?, Name::Create)?;
        let arg = fuse_link_in { oldnodeid: node };
        let entry = self
            .fuse
            .make(fuse_opcode::FUSE_LINK, dir, &[arg.as_bytes(), name, b"\0"])?;
        put_post_op(out, Some(&entry.attr));
        put_no_wcc(out);
        Ok(())
    }

    /// READDIR, or with `plus` READDIRPLUS, which adds each entry's attributes and handle
    fn readdir(&self, a: &mut Reader<'_>, out: &mut Vec<u8>, plus: bool) -> Result {
        let dir = self.handle(a)?;
        let cookie = a.u64()?;
        // The cookie verifier: cookies are FUSE offsets, which are not checked
        a.fixed(8)?;
        let (dircount, maxcount) = if plus {
            (a.u32()? as usize, a.u32()? as usize)
        } else {
            let count = a.u32()? as usize;
            (count, count)
        };
        // status, dir_attributes, cookieverf, the list's end, eof
        let mut size = 4 + 4 + 8 + 4 + 4;
        let mut dirsize = 0;
        let (entries, mut eof) = self.fuse.read_dir(dir, cookie, |name| {
            let dirpart = 4 + 8 + 4 + name.len().next_multiple_of(4) + 8;
            // name_attributes, and name_handle: present, its length and the handle
            let entry = if plus {
                dirpart + 4 + 84 + 4 + 4 + 16
            } else {
                dirpart
            };
            let fits = size + entry <= maxcount && dirsize + dirpart <= dircount;
            if fits {
                size += entry;
                dirsize += dirpart;
            }
            fits
        })?;
        if entries.is_empty() && !eof {
            return Err(Error::Status(NFS3ERR_TOOSMALL));
        }
        put_post_op(out, None);
        out.put_fixed(&[0; 8]);
        let started = Instant::now();
        for (listed, DirEntry { name, ino, cookie }) in entries.into_iter().enumerate() {
            // Looking each entry up may take long: the client asks again for the rest
            if plus && listed > 0 && started.elapsed() > READDIR_BUDGET {
                eof = false;
                break;
            }
            out.put_bool(true);
            out.put_u64(ino);
            out.put_opaque(&name);
            out.put_u64(cookie);
            if plus {
                // "." and ".." as LOOKUP answers them: FUSE filesystems need not
                let found = if name == b"." || name == b".." {
                    self.fuse
                        .resolve(dir, &name)
                        .and_then(|node| self.fuse.getattr(node).map(|attr| (node, attr)))
                } else {
                    self.fuse
                        .lookup(dir, &name)
                        .map(|entry| (entry.nodeid, entry.attr))
                };
                match found {
                    Ok((node, attr)) => {
                        put_post_op(out, Some(&attr));
                        out.put_bool(true);
                        self.put_handle(out, node);
                    }
                    // Gone since it was listed: the client looks it up if it wants it
                    Err(_) => {
                        put_post_op(out, None);
                        out.put_bool(false);
                    }
                }
            }
        }
        out.put_bool(false);
        out.put_bool(eof);
        Ok(())
    }

    fn fsstat(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let st = self.fuse.statfs(self.handle(a)?)?;
        let unit = u64::from(if st.frsize == 0 { st.bsize } else { st.frsize });
        put_post_op(out, None);
        out.put_u64(st.blocks.saturating_mul(unit));
        out.put_u64(st.bfree.saturating_mul(unit));
        out.put_u64(st.bavail.saturating_mul(unit));
        out.put_u64(st.files);
        out.put_u64(st.ffree);
        out.put_u64(st.ffree);
        // invarsec: it may change at any time
        out.put_u32(0);
        Ok(())
    }

    fn fsinfo(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        self.handle(a)?;
        put_post_op(out, None);
        // rtmax, rtpref, rtmult, wtmax, wtpref, wtmult and dtpref: reads are split into FUSE
        // requests here, so the client may ask for as much as it likes
        for value in [MAX_IO, MAX_IO, 4096, MAX_IO, MAX_IO, 4096, READDIR_SIZE] {
            out.put_u32(value);
        }
        out.put_u64(i64::MAX as u64);
        // time_delta: one nanosecond
        out.put_u32(0);
        out.put_u32(1);
        // FSF_LINK, FSF_SYMLINK, FSF_HOMOGENEOUS, FSF_CANSETTIME
        out.put_u32(0x1 | 0x2 | 0x8 | 0x10);
        Ok(())
    }

    fn pathconf(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        // Clients size names by name_max: what the filesystem reports, else what the kernel
        // module does
        let name_max = match self.fuse.statfs(node) {
            Ok(st) if st.namelen != 0 => st.namelen,
            _ => 255,
        };
        put_post_op(out, None);
        // linkmax
        out.put_u32(u32::from(u16::MAX));
        out.put_u32(name_max);
        // no_trunc, chown_restricted, case_insensitive, case_preserving
        for value in [true, true, false, true] {
            out.put_bool(value);
        }
        Ok(())
    }

    fn commit(&self, a: &mut Reader<'_>, out: &mut Vec<u8>) -> Result {
        let node = self.handle(a)?;
        // offset and count: the whole file is committed
        a.u64()?;
        a.u32()?;
        let before = self.fuse.getattr(node).ok();
        self.fuse.fsync(node)?;
        put_wcc(out, before.as_ref(), self.fuse.getattr(node).ok().as_ref());
        out.put_fixed(&self.verifier);
        Ok(())
    }
}

fn sattr(a: &mut Reader<'_>) -> xdr::Result<Sattr> {
    fn time(a: &mut Reader<'_>) -> xdr::Result<SetTime> {
        Ok(match a.u32()? {
            0 => SetTime::Keep,
            1 => SetTime::Now,
            2 => SetTime::At(a.u32()?, a.u32()?),
            _ => return Err(xdr::Garbage),
        })
    }
    Ok(Sattr {
        mode: if a.bool()? { Some(a.u32()?) } else { None },
        uid: if a.bool()? { Some(a.u32()?) } else { None },
        gid: if a.bool()? { Some(a.u32()?) } else { None },
        size: if a.bool()? { Some(a.u64()?) } else { None },
        atime: time(a)?,
        mtime: time(a)?,
    })
}

/// The `FUSE_SETATTR` that sets `attr`, but for its mode with `skip_mode`. None if there is
/// nothing to set
pub(super) fn setattr_in(attr: &Sattr, skip_mode: bool) -> Option<fuse_setattr_in> {
    let mut arg = fuse_setattr_in::new_zeroed();
    let mut valid = FattrFlags::empty();
    if let Some(mode) = attr.mode.filter(|_| !skip_mode) {
        valid |= FattrFlags::FATTR_MODE;
        arg.mode = mode & 0o7777;
    }
    if let Some(uid) = attr.uid {
        valid |= FattrFlags::FATTR_UID;
        arg.uid = uid;
    }
    if let Some(gid) = attr.gid {
        valid |= FattrFlags::FATTR_GID;
        arg.gid = gid;
    }
    if let Some(size) = attr.size {
        valid |= FattrFlags::FATTR_SIZE;
        arg.size = size;
    }
    match attr.atime {
        SetTime::Keep => {}
        SetTime::Now => valid |= FattrFlags::FATTR_ATIME | FattrFlags::FATTR_ATIME_NOW,
        SetTime::At(seconds, nanoseconds) => {
            valid |= FattrFlags::FATTR_ATIME;
            arg.atime = seconds.into();
            arg.atimensec = nanoseconds;
        }
    }
    match attr.mtime {
        SetTime::Keep => {}
        SetTime::Now => valid |= FattrFlags::FATTR_MTIME | FattrFlags::FATTR_MTIME_NOW,
        SetTime::At(seconds, nanoseconds) => {
            valid |= FattrFlags::FATTR_MTIME;
            arg.mtime = seconds.into();
            arg.mtimensec = nanoseconds;
        }
    }
    arg.valid = valid.bits();
    (!valid.is_empty()).then_some(arg)
}

fn put_fattr(out: &mut Vec<u8>, attr: &fuse_attr) {
    let ftype = match attr.mode & S_IFMT {
        S_IFDIR => NF3DIR,
        S_IFLNK => NF3LNK,
        S_IFBLK => NF3BLK,
        S_IFCHR => NF3CHR,
        S_IFIFO => NF3FIFO,
        S_IFSOCK => NF3SOCK,
        _ => NF3REG,
    };
    out.put_u32(ftype);
    out.put_u32(attr.mode & 0o7777);
    out.put_u32(attr.nlink);
    out.put_u32(attr.uid);
    out.put_u32(attr.gid);
    out.put_u64(attr.size);
    out.put_u64(attr.blocks.saturating_mul(512));
    let rdev = attr.rdev as libc::dev_t;
    out.put_u32(libc::major(rdev) as u32);
    out.put_u32(libc::minor(rdev) as u32);
    // fsid
    out.put_u64(0);
    out.put_u64(attr.ino);
    for (seconds, nanoseconds) in [
        (attr.atime, attr.atimensec),
        (attr.mtime, attr.mtimensec),
        (attr.ctime, attr.ctimensec),
    ] {
        out.put_u32(seconds.clamp(0, u32::MAX.into()) as u32);
        out.put_u32(nanoseconds);
    }
}

fn put_post_op(out: &mut Vec<u8>, attr: Option<&fuse_attr>) {
    out.put_bool(attr.is_some());
    if let Some(attr) = attr {
        put_fattr(out, attr);
    }
}

/// How long a listing with attributes may spend looking its entries up before it answers with
/// those it has: clients give up on calls that take seconds
pub(super) const READDIR_BUDGET: Duration = Duration::from_millis(100);

/// The longest name taken, as Linux's and macOS's NAME_MAX
pub(super) const NAME_MAX: usize = 255;

/// What a name in a request is for, which decides what "." and ".." get
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Name {
    Lookup,
    Create,
    Unlink,
    Rmdir,
    Rename,
}

/// A name from a request, checked as the kernel would before passing it on: not empty, without
/// '/' or NUL, and no longer than NAME_MAX. "." and ".." name the directory and its parent,
/// which only a lookup may: anything else gets what POSIX says, rather than reaching the
/// filesystem, which might act on the parent
pub(super) fn name_arg(name: &[u8], name_use: Name) -> std::result::Result<&[u8], i32> {
    if name.is_empty() || name.contains(&b'/') || name.contains(&0) {
        return Err(libc::EINVAL);
    }
    if name.len() > NAME_MAX {
        return Err(libc::ENAMETOOLONG);
    }
    let dot = name == b".";
    if !dot && name != b".." {
        return Ok(name);
    }
    match name_use {
        Name::Lookup => Ok(name),
        Name::Create => Err(libc::EEXIST),
        // Both are directories
        Name::Unlink => Err(libc::EPERM),
        Name::Rmdir if dot => Err(libc::EINVAL),
        Name::Rmdir => Err(libc::ENOTEMPTY),
        Name::Rename => Err(libc::EINVAL),
    }
}

/// `wcc_data`: the size and times from before an operation, and the attributes after
fn put_wcc(out: &mut Vec<u8>, before: Option<&fuse_attr>, after: Option<&fuse_attr>) {
    out.put_bool(before.is_some());
    if let Some(attr) = before {
        out.put_u64(attr.size);
        for (seconds, nanoseconds) in [(attr.mtime, attr.mtimensec), (attr.ctime, attr.ctimensec)] {
            out.put_u32(seconds.clamp(0, u32::MAX.into()) as u32);
            out.put_u32(nanoseconds);
        }
    }
    put_post_op(out, after);
}

/// `wcc_data` without attributes from before or after
fn put_no_wcc(out: &mut Vec<u8>) {
    out.put_bool(false);
    out.put_bool(false);
}

/// The NFS status for an errno. NFSv3 has a status for most of what a filesystem would reply;
/// the rest become `NFS3ERR_IO`
pub(super) fn nfsstat(errno: i32) -> u32 {
    match errno {
        libc::EPERM => 1,
        libc::ENOENT => 2,
        libc::ENXIO => 6,
        libc::EACCES => 13,
        libc::EEXIST => 17,
        libc::EXDEV => 18,
        libc::ENODEV => 19,
        libc::ENOTDIR => 20,
        libc::EISDIR => 21,
        libc::EINVAL => 22,
        libc::EFBIG => 27,
        libc::ENOSPC => 28,
        libc::EROFS => NFS3ERR_ROFS,
        libc::EMLINK => 31,
        libc::ENAMETOOLONG => 63,
        libc::ENOTEMPTY => 66,
        libc::EDQUOT => 69,
        libc::ESTALE => 70,
        libc::ENOSYS | libc::ENOTSUP => NFS3ERR_NOTSUPP,
        // The same number elsewhere
        #[cfg(target_os = "macos")]
        libc::EOPNOTSUPP => NFS3ERR_NOTSUPP,
        _ => NFS3ERR_IO,
    }
}
