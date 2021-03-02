//! Analogue of fusexmp
//!
//! See also a more high-level example: https://github.com/wfraser/fuse-mt/tree/master/example
#![allow(clippy::too_many_arguments)]

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use libc::c_int;
use libc::{EINVAL, EIO, ENOENT, ENOSYS, EPERM};
use libc::{O_ACCMODE, O_APPEND, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY};
use std::{
    convert::TryInto,
    env,
    fs::{File, OpenOptions},
    sync::Arc,
};
use std::{
    ffi::{OsStr, OsString},
    os::unix::prelude::{AsRawFd, FromRawFd, IntoRawFd},
};
use std::{
    path::PathBuf,
    time::{Duration, UNIX_EPOCH},
};
use tokio::sync::Mutex;

use async_trait::async_trait;
use dashmap::DashMap;
use log::error;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::SystemTime;

const TTL: Duration = Duration::from_secs(1); // 1 second

struct DirInfo {
    ino: u64,
    name: OsString,
    kind: FileType,
}

struct XmpFS {
    /// I don't want to include `slab` in dev-dependencies, so using a counter instead.
    /// This provides a source of new inodes and filehandles
    counter: std::sync::atomic::AtomicU64,
    mount_src: OsString,
    inode_to_physical_path: dashmap::DashMap<u64, OsString>,
    mounted_path_to_inode: DashMap<OsString, u64>,
    opened_directories: Arc<Mutex<HashMap<u64, Vec<DirInfo>>>>,
    opened_files: DashMap<u64, std::fs::File>,
}

fn read_blocking(f: File, size: usize, offset: i64) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0; size];

    use std::os::unix::fs::FileExt;

    f.read_at(&mut b[..], offset as u64)?;
    f.into_raw_fd();

    Ok(b)
}

impl XmpFS {
    pub fn new(mount_src: &OsString) -> XmpFS {
        XmpFS {
            counter: std::sync::atomic::AtomicU64::new(1),
            mount_src: mount_src.to_owned(),
            inode_to_physical_path: DashMap::with_capacity(1024),
            mounted_path_to_inode: DashMap::with_capacity(1024),
            opened_directories: Arc::new(Mutex::new(HashMap::with_capacity(2))),
            opened_files: DashMap::new(),
        }
    }

    pub async fn populate_root_dir(&mut self) {
        let rootino = self
            .add_inode(OsStr::from_bytes(b"/"), &self.mount_src)
            .await;
        assert_eq!(rootino, 1);
    }

    pub async fn add_inode(&self, mounted_path: &OsStr, physical_path: &OsStr) -> u64 {
        let ino = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.mounted_path_to_inode
            .insert(mounted_path.to_os_string(), ino);
        self.inode_to_physical_path
            .insert(ino, physical_path.to_os_string());
        ino
    }

    fn mounted_path_to_physical_path(&self, mounted_path: &Path) -> std::path::PathBuf {
        let mount_root = Path::new(&self.mount_src);
        mount_root.join(mounted_path)
    }

    pub async fn add_or_create_inode(&self, mounted_path: impl AsRef<Path>) -> u64 {
        if let Some(x) = self
            .mounted_path_to_inode
            .get(mounted_path.as_ref().as_os_str())
        {
            return *x;
        }

        let mounted_path_ref: &Path = mounted_path.as_ref();

        self.add_inode(
            mounted_path_ref.as_os_str(),
            self.mounted_path_to_physical_path(mounted_path_ref)
                .as_os_str(),
        )
        .await
    }
    pub async fn get_inode(&self, path: impl AsRef<Path>) -> Option<u64> {
        self.mounted_path_to_inode
            .get(path.as_ref().as_os_str())
            .map(|x| *x)
    }

    pub async fn unregister_ino(&self, ino: u64) {
        if !self.inode_to_physical_path.contains_key(&ino) {
            return;
        }
        self.mounted_path_to_inode
            .remove(&*self.inode_to_physical_path.get(&ino).unwrap());
        self.inode_to_physical_path.remove(&ino);
    }

    fn entry_path_from_parentino_and_name(&self, parent: u64, name: &OsStr) -> Option<PathBuf> {
        match self.inode_to_physical_path.get(&parent) {
            None => None,
            Some(parent) => {
                let parent_path = Path::new(parent.value());
                Some(parent_path.join(name))
            }
        }
    }
}

fn ft2ft(t: std::fs::FileType) -> FileType {
    match t {
        x if x.is_symlink() => FileType::Symlink,
        x if x.is_dir() => FileType::Directory,
        x if x.is_file() => FileType::RegularFile,
        x if x.is_fifo() => FileType::NamedPipe,
        x if x.is_char_device() => FileType::CharDevice,
        x if x.is_block_device() => FileType::BlockDevice,
        x if x.is_socket() => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn meta2attr(m: &std::fs::Metadata, ino: u64) -> FileAttr {
    FileAttr {
        ino,
        size: m.size(),
        blocks: m.blocks(),
        atime: m.accessed().unwrap_or(UNIX_EPOCH),
        mtime: m.modified().unwrap_or(UNIX_EPOCH),
        ctime: UNIX_EPOCH + Duration::from_secs(m.ctime().try_into().unwrap_or(0)),
        crtime: m.created().unwrap_or(UNIX_EPOCH),
        kind: ft2ft(m.file_type()),
        perm: m.permissions().mode() as u16,
        nlink: m.nlink() as u32,
        uid: m.uid(),
        gid: m.gid(),
        rdev: m.rdev() as u32,
        flags: 0,
        blksize: m.blksize() as u32,
        padding: 0,
    }
}

async fn errhandle<T: std::future::Future>(
    e: std::io::Error,
    not_found: impl FnOnce() -> Option<T>,
) -> libc::c_int {
    match e.kind() {
        ErrorKind::PermissionDenied => EPERM,
        ErrorKind::NotFound => {
            if let Some(f) = not_found() {
                f.await;
            }
            ENOENT
        }
        e => {
            error!("{:?}", e);
            EIO
        }
    }
}

async fn errhandle_no_cleanup(e: std::io::Error) -> libc::c_int {
    match e.kind() {
        ErrorKind::PermissionDenied => EPERM,
        ErrorKind::NotFound => ENOENT,
        e => {
            error!("{:?}", e);
            EIO
        }
    }
}

#[async_trait]
impl Filesystem for XmpFS {
    async fn init(
        &self,
        _req: &Request<'_>,
        config: &mut fuser::KernelConfig,
    ) -> Result<(), c_int> {
        config.set_max_write(16 * 1024 * 1024).unwrap();
        #[cfg(feature = "abi-7-13")]
        config.set_max_background(512).unwrap();
        Ok(())
    }
    async fn lookup(&self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if !self.inode_to_physical_path.contains_key(&parent) {
            return reply.error(ENOENT).await;
        }

        let entry_path = {
            let tmp_v = self.inode_to_physical_path.get(&parent).unwrap();
            let parent_path = Path::new(&*tmp_v);
            parent_path.join(name).to_owned()
        };
        let entry_inode = self.get_inode(&entry_path).await;

        match std::fs::symlink_metadata(&entry_path) {
            Err(e) => {
                reply
                    .error(
                        errhandle(e, || {
                            // if not found:
                            if let Some(ino) = entry_inode {
                                Some(self.unregister_ino(ino))
                            } else {
                                None
                            }
                        })
                        .await,
                    )
                    .await
            }
            Ok(m) => {
                let ino = match entry_inode {
                    Some(x) => x,
                    None => self.add_or_create_inode(entry_path).await,
                };

                let attr: FileAttr = meta2attr(&m, ino);

                return reply.entry(&TTL, &attr, 1).await;
            }
        }
    }

    async fn getattr(&self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        if !self.inode_to_physical_path.contains_key(&ino) {
            return reply.error(ENOENT).await;
        }

        let metadata = {
            let tmp_ref = self.inode_to_physical_path.get(&ino).unwrap();
            let entry_path = Path::new(&*tmp_ref);

            std::fs::symlink_metadata(entry_path)
        };
        match metadata {
            Err(e) => {
                reply
                    .error(
                        errhandle(e, || {
                            // if not found:

                            Some(self.unregister_ino(ino))
                        })
                        .await,
                    )
                    .await;
            }
            Ok(m) => {
                let attr: FileAttr = meta2attr(&m, ino);
                reply.attr(&TTL, &attr).await;
            }
        }
    }

    async fn open(&self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if !self.inode_to_physical_path.contains_key(&ino) {
            return reply.error(ENOENT).await;
        }

        let mut oo = OpenOptions::new();

        let fl = flags as c_int;
        match fl & O_ACCMODE {
            O_RDONLY => {
                oo.read(true);
                oo.write(false);
            }
            O_WRONLY => {
                oo.read(false);
                oo.write(true);
            }
            O_RDWR => {
                oo.read(true);
                oo.write(true);
            }
            _ => return reply.error(EINVAL).await,
        }

        oo.create(false);
        if fl & (O_EXCL | O_CREAT) != 0 {
            error!("Wrong flags on open");
            return reply.error(EIO).await;
        }

        oo.append(fl & O_APPEND == O_APPEND);
        oo.truncate(fl & O_TRUNC == O_TRUNC);

        let p = self.inode_to_physical_path.get(&ino).unwrap().clone();
        let entry_path = Path::new(&p);

        match oo.open(entry_path) {
            Err(e) => {
                reply
                    .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                    .await
            }
            Ok(f) => {
                let ino = self
                    .counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                self.opened_files.insert(ino, f);
                reply.opened(ino, 0).await;
            }
        }
    }

    async fn create(
        &self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,

        flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.inode_to_physical_path.get(&parent) {
            None => return reply.error(ENOENT).await,
            Some(parent_path) => parent_path.to_owned(),
        };

        let parent_path = Path::new(&parent_path);
        let entry_path = parent_path.join(name);

        let ino = self.add_or_create_inode(&entry_path).await;

        let mut oo = OpenOptions::new();

        let fl = flags as c_int;
        match fl & O_ACCMODE {
            O_RDONLY => {
                oo.read(true);
                oo.write(false);
            }
            O_WRONLY => {
                oo.read(false);
                oo.write(true);
            }
            O_RDWR => {
                oo.read(true);
                oo.write(true);
            }
            _ => return reply.error(EINVAL).await,
        }

        oo.create(fl & O_CREAT == O_CREAT);
        oo.create_new(fl & O_EXCL == O_EXCL);
        oo.append(fl & O_APPEND == O_APPEND);
        oo.truncate(fl & O_TRUNC == O_TRUNC);
        oo.mode(mode);

        match oo.open(&entry_path) {
            Err(e) => {
                return reply
                    .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                    .await
            }
            Ok(f) => {
                let meta = match std::fs::symlink_metadata(entry_path) {
                    Err(e) => {
                        return reply
                            .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                            .await;
                    }
                    Ok(m) => meta2attr(&m, ino),
                };
                let fh = self
                    .counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                self.opened_files.insert(fh, f);
                reply.created(&TTL, &meta, 1, fh, 0).await
            }
        }
    }

    async fn read(
        &self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,

        reply: ReplyData,
    ) {
        let file_opt = self.opened_files.get(&fh); //;.map(|e| e.try_clone().unwrap());
        let f = match file_opt {
            None => {
                return reply.error(EIO).await;
            }
            Some(f) => unsafe { File::from_raw_fd(f.as_raw_fd()) },
        };

        let size = size as usize;

        let b = tokio::task::spawn_blocking(move || read_blocking(f, size, offset))
            .await
            .unwrap();

        match b {
            Ok(b) => {
                reply.data(&b[..]).await;
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    reply.data(&[]).await;
                }
                _ => {
                    return reply.error(errhandle_no_cleanup(e).await).await;
                }
            },
        }
    }

    async fn write(
        &self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let file_opt = self.opened_files.get(&fh);
        let f = match file_opt {
            None => {
                return reply.error(EIO).await;
            }
            Some(f) => unsafe { File::from_raw_fd(f.as_raw_fd()) },
        };

        use std::os::unix::fs::FileExt;
        match f.write_all_at(data, offset as u64) {
            Err(e) => {
                f.into_raw_fd();
                return reply.error(errhandle_no_cleanup(e).await).await;
            }
            Ok(()) => {
                f.into_raw_fd();
                reply.written(data.len() as u32).await;
            }
        };
    }

    async fn fsync(
        &self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        if !self.opened_files.contains_key(&fh) {
            reply.error(EIO).await;
            return;
        }

        let f = self.opened_files.get_mut(&fh).unwrap();

        match if datasync {
            f.sync_data()
        } else {
            f.sync_all()
        } {
            Err(e) => {
                reply.error(errhandle_no_cleanup(e).await).await;
                return;
            }
            Ok(()) => {
                reply.ok().await;
            }
        }
    }

    async fn fsyncdir(
        &self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        // I'm not sure how to do I with libstd
        reply.ok().await;
    }

    async fn release(
        &self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.opened_files.remove(&fh) {
            Some(_) => {
                reply.ok().await;
            }
            None => {
                reply.error(EIO).await;
            }
        }
    }

    async fn opendir(&self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        if !self.inode_to_physical_path.contains_key(&ino) {
            return reply.error(ENOENT).await;
        }

        let entry_path = Path::new(&*self.inode_to_physical_path.get(&ino).unwrap()).to_owned();

        match std::fs::read_dir(&entry_path) {
            Err(e) => {
                reply.error(errhandle_no_cleanup(e).await).await;
            }
            Ok(x) => {
                let mut v: Vec<DirInfo> = Vec::with_capacity(x.size_hint().0);

                let parent_ino: u64 = if ino == 1 {
                    1
                } else {
                    match entry_path.parent() {
                        None => ino,
                        Some(x) => self
                            .mounted_path_to_inode
                            .get(x.as_os_str())
                            .map(|e| *e.value())
                            .unwrap_or(ino),
                    }
                };

                v.push(DirInfo {
                    ino,
                    kind: FileType::Directory,
                    name: OsStr::from_bytes(b".").to_os_string(),
                });
                v.push(DirInfo {
                    ino: parent_ino,
                    kind: FileType::Directory,
                    name: OsStr::from_bytes(b"..").to_os_string(),
                });

                for dee in x {
                    match dee {
                        Err(e) => {
                            reply.error(errhandle_no_cleanup(e).await).await;
                            return;
                        }
                        Ok(de) => {
                            let name = de.file_name().to_os_string();
                            let kind = de.file_type().map(ft2ft).unwrap_or(FileType::RegularFile);
                            let jp = entry_path.join(&name);
                            let ino = self.add_or_create_inode(jp).await;

                            v.push(DirInfo { ino, kind, name });
                        }
                    }
                }
                let fh = self
                    .counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                self.opened_directories.lock().await.insert(fh, v);
                reply.opened(fh, 0).await;
            }
        }
    }

    async fn readdir(
        &self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let handle = self.opened_directories.lock().await;
        if !handle.contains_key(&fh) {
            error!("no fh {} for readdir", fh);
            return reply.error(EIO).await;
        }

        let entries = &handle[&fh];

        for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(entry.ino, (i + 1) as i64, entry.kind, &entry.name) {
                break;
            }
        }
        reply.ok().await
    }

    async fn releasedir(
        &self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        let mut handle = self.opened_directories.lock().await;
        if !handle.contains_key(&fh) {
            reply.error(EIO).await;
            return;
        }

        handle.remove(&fh);
        reply.ok().await;
    }

    async fn readlink(&self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        if let Some(p) = self.inode_to_physical_path.get(&ino) {
            let entry_path = Path::new(p.value());
            match std::fs::read_link(entry_path) {
                Err(e) => {
                    reply
                        .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                        .await
                }
                Ok(x) => {
                    reply.data(x.as_os_str().as_bytes()).await;
                }
            }
        } else {
            return reply.error(ENOENT).await;
        };
    }

    async fn mkdir(
        &self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let entry_path = if let Some(p) = self.entry_path_from_parentino_and_name(parent, name) {
            p
        } else {
            return reply.error(ENOENT).await;
        };

        let ino = self.add_or_create_inode(&entry_path).await;
        match std::fs::create_dir(&entry_path) {
            Err(e) => reply.error(errhandle_no_cleanup(e).await).await,
            Ok(()) => {
                let attr = match std::fs::symlink_metadata(entry_path) {
                    Err(e) => {
                        return reply
                            .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                            .await;
                    }
                    Ok(m) => meta2attr(&m, ino),
                };

                reply.entry(&TTL, &attr, 1).await;
            }
        }
    }

    async fn unlink(&self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.inode_to_physical_path.get(&parent) {
            None => reply.error(ENOENT).await,
            Some(p) => {
                let parent_path = Path::new(&*p);
                let entry_path = parent_path.join(name);

                match std::fs::remove_file(entry_path) {
                    Err(e) => reply.error(errhandle_no_cleanup(e).await).await,
                    Ok(()) => reply.ok().await,
                }
            }
        }
    }

    async fn rmdir(&self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if !self.inode_to_physical_path.contains_key(&parent) {
            return reply.error(ENOENT).await;
        }

        let parent_path =
            Path::new(&self.inode_to_physical_path.get(&parent).unwrap().value()).to_owned();
        let entry_path = parent_path.join(name);

        match std::fs::remove_dir(entry_path) {
            Err(e) => reply.error(errhandle_no_cleanup(e).await).await,
            Ok(()) => {
                reply.ok().await;
            }
        }
    }

    async fn symlink(
        &self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        if !self.inode_to_physical_path.contains_key(&parent) {
            return reply.error(ENOENT).await;
        }

        let parent_path =
            Path::new(&self.inode_to_physical_path.get(&parent).unwrap().value()).to_owned();
        let entry_path = parent_path.join(name);
        let ino = self.add_or_create_inode(&entry_path).await;

        match std::os::unix::fs::symlink(&entry_path, link) {
            Err(e) => {
                reply
                    .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                    .await
            }
            Ok(()) => {
                let attr = match std::fs::symlink_metadata(entry_path) {
                    Err(e) => {
                        return reply
                            .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                            .await;
                    }
                    Ok(m) => meta2attr(&m, ino),
                };

                reply.entry(&TTL, &attr, 1).await;
            }
        }
    }

    async fn rename(
        &self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,

        reply: ReplyEmpty,
    ) {
        if !self.inode_to_physical_path.contains_key(&parent) {
            return reply.error(ENOENT).await;
        }
        if !self.inode_to_physical_path.contains_key(&newparent) {
            return reply.error(ENOENT).await;
        }

        let parent_path =
            Path::new(&self.inode_to_physical_path.get(&parent).unwrap().value()).to_owned();
        let newparent_path =
            Path::new(&self.inode_to_physical_path.get(&newparent).unwrap().value()).to_owned();

        let entry_path = parent_path.join(name);
        let newentry_path = newparent_path.join(newname);

        if entry_path == newentry_path {
            return reply.ok().await;
        }

        let ino = self.add_or_create_inode(&entry_path).await;

        match std::fs::rename(&entry_path, &newentry_path) {
            Err(e) => {
                reply
                    .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                    .await
            }
            Ok(()) => {
                self.inode_to_physical_path
                    .insert(ino, newentry_path.as_os_str().to_os_string());
                self.mounted_path_to_inode.remove(entry_path.as_os_str());
                self.mounted_path_to_inode
                    .insert(newentry_path.as_os_str().to_os_string(), ino);
                reply.ok().await;
            }
        }
    }

    async fn link(
        &self,
        _req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // Not a true hardlink: new inode
        if !self.inode_to_physical_path.contains_key(&ino) {
            return reply.error(ENOENT).await;
        }
        if !self.inode_to_physical_path.contains_key(&newparent) {
            return reply.error(ENOENT).await;
        }

        let entry_path =
            Path::new(&self.inode_to_physical_path.get(&ino).unwrap().value()).to_owned();
        let newparent_path =
            Path::new(&self.inode_to_physical_path.get(&newparent).unwrap().value()).to_owned();
        let newentry_path = newparent_path.join(newname);

        let newino = self.add_or_create_inode(&newentry_path).await;

        match std::fs::hard_link(&entry_path, &newentry_path) {
            Err(e) => {
                reply
                    .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                    .await
            }
            Ok(()) => {
                let attr = match std::fs::symlink_metadata(newentry_path) {
                    Err(e) => {
                        return reply
                            .error(errhandle(e, || Some(self.unregister_ino(newino))).await)
                            .await;
                    }
                    Ok(m) => meta2attr(&m, newino),
                };

                reply.entry(&TTL, &attr, 1).await;
            }
        }
    }

    async fn mknod(
        &self,
        _req: &Request<'_>,
        _parent: u64,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        // no mknod lib libstd
        reply.error(ENOSYS).await;
    }

    async fn setattr(
        &self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Limited to setting file length only

        let (fh, sz) = match (fh, size) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                // only partial for chmod +x, and not the good one

                let entry_path =
                    Path::new(&self.inode_to_physical_path.get(&ino).unwrap().value()).to_owned();

                if let Some(mode) = mode {
                    use std::fs::Permissions;

                    let perm = Permissions::from_mode(mode);
                    match std::fs::set_permissions(&entry_path, perm) {
                        Err(e) => {
                            return reply
                                .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                                .await
                        }
                        Ok(()) => {
                            let attr = match std::fs::symlink_metadata(entry_path) {
                                Err(e) => {
                                    return reply
                                        .error(
                                            errhandle(e, || Some(self.unregister_ino(ino))).await,
                                        )
                                        .await;
                                }
                                Ok(m) => meta2attr(&m, ino),
                            };

                            return reply.attr(&TTL, &attr).await;
                        }
                    }
                } else {
                    // Just try to do nothing, successfully.
                    let attr = match std::fs::symlink_metadata(entry_path) {
                        Err(e) => {
                            return reply
                                .error(errhandle(e, || Some(self.unregister_ino(ino))).await)
                                .await;
                        }
                        Ok(m) => meta2attr(&m, ino),
                    };

                    return reply.attr(&TTL, &attr).await;
                }
            }
        };

        if !self.opened_files.contains_key(&fh) {
            return reply.error(EIO).await;
        }

        let f = self.opened_files.get_mut(&fh).unwrap();

        match f.set_len(sz) {
            Err(e) => reply.error(errhandle_no_cleanup(e).await).await,
            Ok(()) => {
                // pull regular file metadata out of thin air

                let attr = FileAttr {
                    ino,
                    size: sz,
                    blocks: 1,
                    atime: UNIX_EPOCH,
                    mtime: UNIX_EPOCH,
                    ctime: UNIX_EPOCH,
                    crtime: UNIX_EPOCH,
                    kind: FileType::RegularFile,
                    perm: 0o644,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    flags: 0,
                    blksize: sz as u32,
                    padding: 0,
                };

                reply.attr(&TTL, &attr).await;
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    env_logger::init();
    let mount_src = env::args_os().nth(1).unwrap();
    let mount_dest = env::args_os().nth(2).unwrap();
    println!("About to mount {:?} onto {:?}", mount_src, mount_dest);

    let options = [
        fuser::MountOption::RW,
        fuser::MountOption::Async,
        fuser::MountOption::FSName(String::from("xmp")),
        fuser::MountOption::AutoUnmount,
    ];
    let mut xmp = XmpFS::new(&mount_src);
    xmp.populate_root_dir().await;
    fuser::mount2(xmp, 16, mount_dest, &options).await.unwrap();
}
