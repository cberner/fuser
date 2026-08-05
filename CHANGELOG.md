# FUSE for Rust - Changelog

## Unreleased
* `KernelConfig::add_capabilities()` now accepts `InitFlags::FUSE_ALLOW_IDMAP` (ABI 7.41),
  which lets the mount be idmapped. It is accepted only where it can be honored - the session
  must allow other users, and `default_permissions` must be in force, whether from
  `MountOption::DefaultPermissions` or from negotiating `InitFlags::FUSE_POSIX_ACL` - and
  refused otherwise: the kernel refuses the connection outright without `default_permissions`,
  and without allow_other fuser would be offering an owner-only ACL it can no longer enforce. Once negotiated the kernel withholds the
  caller's ids from every request that does not create an inode, so `Request::uid()` and
  `Request::gid()` report the new `FUSE_INVALID_UIDGID` there; the requests that do create an
  inode still carry ids, and they are the owner the new inode should get, already mapped
* Add `Filesystem::statx()`, which the kernel calls for `statx(2)` (ABI 7.38), along with
  `StatxAttr` and `ReplyStatx`. This exists to report a creation time, which no other request
  can carry: `fuse_attr` has a field for it on macOS alone, so on Linux `statx(2)` otherwise
  reports whatever the kernel cached. Leaving it unimplemented reports `ENOSYS`, which the
  kernel takes as permanent: it stops sending `FUSE_STATX` on that connection and answers
  `statx(2)` out of `getattr()`, which is what happened before. Note that `StatxAttr` also
  carries the `STATX_ATTR_*` properties, such as immutable and append-only, because the wire
  format does - but the kernel discards them from a FUSE reply, so setting them does not make
  `chattr +i` visible to `statx(2)`
* Add `Filesystem::tmpfile()`, which the kernel calls for `open()` with `O_TMPFILE` (#366,
  ABI 7.37). The file has no name and belongs to no directory until `linkat()` gives it one,
  so unlike `create()` this is told only which directory it was made in. Leaving it
  unimplemented reports `ENOSYS`, which the kernel takes as permanent: it stops offering
  `O_TMPFILE` on that connection and answers `EOPNOTSUPP`, which is what happened before
* Add `Filesystem::syncfs()`, which the kernel calls for `syncfs(2)` (#359, ABI 7.34). Leaving
  it unimplemented reports `ENOSYS`, which makes the kernel stop asking for the lifetime of the
  connection, so this changes nothing for a filesystem that does not want it. Note that the
  kernel only propagates `syncfs(2)` on `fuseblk` and virtiofs connections, neither of which
  fuser mounts, so this is reachable only for a session built with `Session::from_fd` on such
  a connection
* Unmounting from within the mounting process now works with `MountOption::AutoUnmount` (#407).
  Dropping the `BackgroundSession`, calling `umount_and_join()` or `SessionUnmounter::unmount()`
  used to leave the unmount to the `fusermount` helper, which only acts once the process exits.
  Until then the mountpoint was left behind as a dangling "transport endpoint is not connected",
  and the session kept running. `auto_unmount` remains a safety net for a process that dies
  without unmounting
* Add `Notifier::inc_epoch()`, which invalidates every cached directory entry at once by
  incrementing the connection's epoch (#382). This costs one notification where
  `inval_entry()` costs one per entry and needs the names up front, so it suits a backing
  store that changed wholesale. Requires ABI 7.44, returning `ENOTSUP` below it, since the
  kernel advertises no capability bit for this and an older one answers only with `EINVAL`
* The ABI version reported to the kernel on non-macOS platforms is now 7.44, up from 7.40, so
  that `inc_epoch()` is in protocol rather than relying on the kernel not version-gating its
  notification dispatch. The features 7.41 through 7.43 add are capabilities the kernel acts
  on only once negotiated, and all three are already refused
* Add `TryFrom<&std::fs::Metadata>` for `FileAttr` (#413), so a filesystem backed by files on
  disk can answer `getattr` and `lookup` from the underlying file's metadata. The conversion is
  fallible because `nlink`, `rdev` and `blksize` narrow to the widths the FUSE protocol gives
  them, and because a file whose type `FileType` cannot represent has no valid conversion. Note
  that `ino` is the underlying file's inode number, which a filesystem assigning its own will
  want to overwrite
* Support `InitFlags::FUSE_HANDLE_KILLPRIV_V2`, which the previous release refused. With it
  negotiated the kernel stops clearing suid and sgid itself and instead tells the filesystem
  which requests must clear them, so `Filesystem::setattr()`, `open()` and `create()` gain a
  `kill_suid_gid` argument carrying that signal (`write()` already had it via
  `WriteFlags::FUSE_WRITE_KILL_SUIDGID`). A filesystem that does not request the capability
  never sees it set. Note that `kill_suid_gid` covers suid and sgid only: as with plain
  `FUSE_HANDLE_KILLPRIV`, clearing the `security.capability` xattr on every write, chown and
  truncate is also the filesystem's job under either capability, and carries no per-request
  signal. What v2 adds is that suid and sgid are cleared only when the caller lacks
  `CAP_FSETID`, matching what the kernel would have done itself
* `KernelConfig::add_capabilities()` now refuses capabilities fuser cannot honor, rather than
  requesting them and leaving the filesystem silently broken: `FUSE_SECURITY_CTX`,
  `FUSE_CREATE_SUPP_GROUP`, `FUSE_HANDLE_KILLPRIV_V2`, `FUSE_ALLOW_IDMAP`, `FUSE_HAS_INODE_DAX`,
  `FUSE_SUBMOUNTS`, `FUSE_MAP_ALIGNMENT`, `FUSE_OVER_IO_URING`, `FUSE_HAS_RESEND` and
  `FUSE_REQUEST_TIMEOUT`. Negotiating most of them merely had no effect, but `FUSE_ALLOW_IDMAP`
  left the filesystem answering `EACCES` to everything but inode creation, and
  `FUSE_HANDLE_KILLPRIV_V2` left suid and sgid bits surviving a chown, a truncate or an
  `O_TRUNC` open. Plain `FUSE_HANDLE_KILLPRIV` still works, as do the macFUSE capabilities that
  share a bit with three of these
* Add `Notifier::expire_entry()`, which marks a cached directory entry for revalidation
  instead of invalidating it (#367). Unlike `inval_entry()`, expiring leaves anything
  mounted beneath the entry mounted, so it suits an entry merely believed to be stale.
  Returns `ENOTSUP` on a kernel that does not advertise `InitFlags::FUSE_HAS_EXPIRE_ONLY`,
  rather than sending a request such a kernel would answer by invalidating the entry and
  reporting success
* Add `ReplyDirectory::remaining_capacity()` and `ReplyDirectoryPlus::remaining_capacity()`,
  which report how much room is left for entries (#214). Before the first entry is added this
  is the buffer size the kernel asked for, so a filesystem can size a batch of work to the
  reply instead of preparing entries only to have `add()` report the buffer full. The
  `experimental` async API exposes the same thing on `DirEntListBuilder`
* Parse the extended `fuse_setxattr_in` layout, making `InitFlags::FUSE_SETXATTR_EXT` usable
  (#357). Enabling that capability previously panicked the session thread on the first
  `setxattr` and left the filesystem hung, because fuser kept reading the shorter pre-7.33
  layout. A `setxattr` whose value length disagrees with its header is now rejected rather
  than panicking, and one carrying `FUSE_SETXATTR_ACL_KILL_SGID` is refused with `ENOTSUP`,
  since `Filesystem::setxattr` cannot yet be told to clear SGID
* Name the file that could not be reached when a mount fails, instead of reporting a bare
  "No such file or directory" that could equally mean the mountpoint, `/dev/fuse` or the
  `fusermount` helper (#250)
* Fix `EBUSY` when unmounting a filesystem that is still in use, as root on Linux (#686).
  The unmount is now lazy, as it already was for unprivileged users and as libfuse does,
  instead of failing and leaving the filesystem mounted with no way to retry
* Fix meaningless errors when a mount fails inside libfuse (#406). A failure that libfuse
  reported without setting errno was surfaced with an unrelated errno, most visibly
  `Success (os error 0)`; such a failure now names the libfuse call it came from, alongside
  libfuse's own diagnostic on stderr
* Dropping a `BackgroundSession` now unmounts the filesystem and waits for the session to
  end, guaranteeing that `Filesystem::destroy` has run when drop returns (#239, #411). This
  restores the pre-0.16 blocking drop behavior. Drop does not wait when the session cannot
  end: sessions created via `Session::from_fd` are left detached (use `join()` after ending
  them), and so are sessions whose unmount failed or whose connection is still alive a few
  seconds after the unmount (e.g. a lazily unmounted filesystem still in use).
  The `guard` field of `BackgroundSession` is now private - use `join()`/`umount_and_join()`
* The pure-rust and `libfuse2` mount backends now report `fusermount` unmount failures
  instead of silently ignoring them
* Treat `ECONNABORTED` from the FUSE device as a clean session end (#212): with
  `FUSE_ABORT_ERROR` negotiated, aborting the connection made `Session::run()` and
  `BackgroundSession::umount_and_join()` return an error instead of ending normally
  the way an unmount (`ENODEV`) does
* `KernelConfig::set_max_write()` now rejects values below 4096 with the nearest valid value,
  per its documented contract (#327). The kernel clamps `max_write` to at least 4096, so a
  smaller value was accepted but ineffective: write requests of up to 4096 bytes still arrived
* Fix inverted mounted-check during session teardown: after the filesystem had already been
  unmounted externally, fuser would attempt to unmount the mountpoint again, which could
  unmount an unrelated filesystem mounted at the same path in the meantime
* Apply the same already-unmounted check to the `libfuse2` and `libfuse3` mount backends,
  fixing the spurious "Failed to umount filesystem" warning when a session is dropped after
  an external unmount (#658). As in libfuse, a connection that was aborted (e.g. via
  fusectl) also counts as already unmounted; its dead mount is left to `auto_unmount` or
  `fusermount -u -z`
* Fix special characters in `MountOption` values being interpreted as further mount options
  (#424). `MountOption::FSName("foo,ro")` used to mount a filesystem named `foo` that was
  read-only, instead of one named `foo,ro`. Commas and backslashes in `FSName` are now escaped
  for libfuse and the fusermount helpers. `Subtype` and `CUSTOM` values containing a comma or
  backslash, which cannot be escaped consistently, are now rejected by `Session::new()`, as are
  NUL bytes in any value, which used to panic. On platforms other than Linux the mount helpers
  support no escaping, so `FSName` is restricted there as well
* Fix a per-mount memory leak in the `libfuse3` backend: the `fuse_session` is now destroyed
  on every teardown path, including when mounting fails partway through setup
* Fix corruption of pre-1970 timestamps with fractional seconds in `setattr`: the nanoseconds
  were subtracted from instead of added to the (negative) whole second, shifting times by up
  to two seconds
* macOS: forward the `renamex_np(2)` flags to `Filesystem::rename()` as
  `RenameFlags::RENAME_SWAP` and `RenameFlags::RENAME_EXCL`, instead of always passing an empty
  set. Filesystems that do not implement these operations must now reply with EINVAL for flags
  they don't handle
* macOS: fix garbled `rename()` names (#341). fuser assumed macFUSE always sends the extended
  16-byte `fuse_rename_in`, but macFUSE sends it only once the extended rename operations have
  been negotiated, which fuser never requested. The 8-byte layout it actually received was then
  parsed at the wrong offset, so the filesystem saw truncated or empty names. fuser now always
  requests those operations
* Remove the `macfuse-4-compat` feature flag, which was set by the build script and selected the
  extended `fuse_rename_in` layout. That layout is now used for all macOS builds

## 0.18.0 - 2026-07-22
* Remove deprecated feature flags `abi-*`
* Rename `mount2()` to `mount()`
* Rename `spawn_mount2()` to `spawn_mount()`
* Make `Session::run()` public, and check mount option conflicts in `Session::new()`
* Add `ReplyEntry::entry_with_ttls()` to reply with distinct entry and attribute TTLs
* Add support for raw marshalling of `BackingId`s across process boundaries via `BackingId::create_raw()`,
  `BackingId::into_raw()`, `ReplyOpen::wrap_backing()`, and `ReplyCreate::wrap_backing()`
* Fix missing `allow_other` mount option on FreeBSD, which caused `EPERM` for non-owner users

## 0.17.0 - 2026-02-14

Major changes:
* Change many integer-based public API parameters to strongly-typed newtypes and bitflags. 
  This breaking changes affects many of the methods on `Filesystem`
* Change `Filesystem` trait methods to use `&self`, and require mounted filesystems to be `Send + Sync + 'static`
* Improve typed error handling across request/reply APIs
* Replace `Vec<MountOption>` mount APIs with a structured `Config` API, including ACL option handling
* Feature flags `abi-7-xx` are now ignored and will be removed in 0.18, with compatibility checks moved to runtime behavior
* Remove the old ABI-specific feature-flag surface (`abi-7-9` through `abi-7-19`, plus tooling/docs/examples references)
* Add support for multiple event loops per session, which can be enabled via `Config::n_threads`
* Add experimental async API (`AsyncFilesystem`)

Minor changes:
* Rename `BackgroundSession::join` to `umount_and_join`, returning `io::Result<()>` instead of panicking
* Add `FUSE_DEV_IOC_CLONE` support and improve passthrough descriptor handling (`ReplyCreate`, `ReplyOpen`, `BackingId`)
* Improve passthrough descriptor handling (`ReplyCreate`, `ReplyOpen`, `BackingId`)
* Add `FileType` conversion from std `FileType`
* Add option to explicitly choose `libfuse2` or `libfuse3`, prefer `libfuse3` by default
* Support building without libfuse on BSD
* Remove remaining `osxfuse` support and improve `macfuse` compatibility
* The path to the `fusermount` binary can be specified with the `FUSERMOUNT_PATH` environment variable
* `allow_root` or `allow_other` must be enabled when using `auto_unmount`
* Remove deprecated `mount` and `spawn_mount` -- use `mount2` and `spawn_mount2` instead
* Update and expand documentation

Internal changes:
* Improve Linux/BSD/macOS test coverage by migrating mount tests to `fuser-tests` and expanding CI
* Rework session lifecycle internals (handshake/session startup, destroy ordering, and unmount error propagation)

## 0.16.0 - 2025-09-12
* Add support for passthrough file descriptors
* Change `KernelConfig` capabilities flags parameters to `u64`
* Remove feature flags `abi-7-9` through `abi-7-18`
* Remove `libfuse` feature flag from defaults. Linking with libfuse can be enabled with the `libfuse` feature flag
* Improve macfuse compatibility (note that macfuse remains untested)
* Fix unsound behavior when linking with libfuse3
* Performance optimizations
* Update documentation

## 0.15.1 - 2024-11-27
* Fix crtime related panic that could occur on MacOS. See PR #322 for details.

## 0.15.0 - 2024-10-25
* Add file handle argument to `getattr()`
* Change `poll()` to take a `PollHandle` instead of a `u64`
* Add low level API for manually mounting or wrapping a fuse file descriptor into a `Session`
* Fix compatibility with MacFUSE 4.x
* Performance optimizations

## 0.14.0 - 2023-11-04
* Add support for poll
* Add support for notifications
* ABI 7.11 support is now complete

## 0.13.0 - 2023-08-16
* Remove dependency on `users` crate
* Performance optimizations

## 0.12.0 - 2022-12-13
* Add method to `Session` to unmount non-`Send` `Filesystem`s

## 0.11.1 - 2022-08-24
* Improve an error message when using libfuse2

## 0.11.0 - 2022-03-05
* Add `spawn_mount2()`
* Deprecate `spawn_mount()`

## 0.10.0 - 2022-01-06
* Improve error messages
* Support compiling with musl
* Default `link()` & `symlink()` now return EPERM instead of ENOSYS

## 0.9.1 - 2021-09-07
* `forget` and `batch_forget` no longer require that `AllowRoot` be set

## 0.9.0 - 2021-08-31
* Ensure that `Filesystem::destroy` is always called, when the filesystem is unmounted
* Remove request parameter from `Filesystem::destroy`.
* Make `fuse_forget_one` public, so that `Filesystem::batch_forget` can be implemented by users.
* Fix `batch_forget`. Previously, it always received an empty list of inodes.
* Fix `MountOption::AllowRoot`. Previously, using it resulted in a crash.
* Fix `MountOption::AutoUnmount` so that it works when `AllowRoot` and `AllowOther` are both not set.
* Make log messages more verbose (now includes the operation)

## 0.8.0 - 2021-06-11
* Deprecate `mount()`
* Remove `FileAttr.padding`. This field was added by mistake, and does nothing
* Fix crash when receiving an unknown FUSE operation type
* Minor performance optimizations

## 0.7.0 - 2021-01-10
* Support building with MacFuse 4.x on OSX
* Support configuring max_write & max_readahead via `KernelConfig` during `init`
* Support configuring filesystem timestamp granularity via `KernelConfig.set_time_granularity` during `init`
* Support requesting additional capability flags via `KernelConfig.add_capabilities` during `init`

## 0.6.0 - 2020-11-22
* Make `spawn_mount()` safe
* Change `flags` parameter of `create()`, `open()`, `opendir()`, `release()`, `releasedir()` to be signed, so that it matches
  libfuse and the associated constants in libc
* Change `flags` parameter of `setxattr()` to be signed, so that it matches libfuse
* Change `mask` parameter of `access()` to be signed, so that it matches libfuse and the associated constants in libc
* Change lock type parameter of `getlk()` and `setlk()` to be signed, so that it matches libfuse and the associated constants in libc
* Change atime & atime_now and mtime & mtime_now parameters of `setattr()` to make their relationship more obvious
* Add `lock_owner` and file `flags` parameters to `read()` and `write()`
* Add `umask` parameter to `mknod()`, `mkdir()` and `create()`
* Add `KernelConfig` parameter to `init()` to allow `Filesystem` to configure the kernel connection attributes
* Add support for `fallocate()`, `ioctl()`, `copy_file_range()`, and `lseek()`
* Add support for FUSE_BATCH_FORGET
* Add support for FUSE_READDIRPLUS
* Add support for FUSE_RENAME2
* Add FUSE_WRITE_KILL_PRIV flag for `write()`
* Add FUSE_WRITEBACK_CACHE flag
* Add FUSE_NO_OPEN_SUPPORT flag
* Add FUSE_PARALLEL_DIROPS flag
* Add FUSE_HANDLE_KILLPRIV flag
* Add FUSE_POSIX_ACL flag
* Add FUSE_ABORT_ERROR flag
* Add FUSE_NO_OPENDIR_SUPPORT flag
* Add FUSE_CACHE_SYMLINKS flag
* Add FUSE_EXPLICIT_INVAL_DATA flag
* Add FUSE_IOCTL_COMPAT_X32 flag
* Add FOPEN_CACHE_DIR flag
* Add FOPEN_STREAM flag
* Add FUSE_MAX_PAGES flag
* Add max_pages, and time_gran support to init code path (these are not currently configurable)
* Add support for ctime in `setattr()`
* Add support for timestamps before the unix epoch in `getattr()` and `setattr()`

## 0.5.0 - 2020-10-17

* Enable FUSE_BIG_WRITES for ABI >= 7.10
* Add FUSE_AUTO_INVAL_DATA constant
* Add ABI 7.20 to 7.31 feature flags. Support for these are incomplete.
* Add support for building with libfuse3
* Add support for building without libfuse/libfuse3 on Linux (i.e. there's now a pure Rust implementation of all features)
* Add `mount2()` with improved option API

## 0.4.1 - 2020-10-12

* Added new feature `serializable` that will enable serde serialization/deserialization for `FileType`, `FileAttr`

## 0.4.0 - 2020-06-18

* Forked as `fuser` crate, at https://github.com/cberner/fuser
* Add ATIME_NOW and MTIME_NOW support
* Add stubs for ioctl, fallocate, and poll for ABI 7.11

## 0.3.1 - 2017-11-08

* Offsets to `read`, `write` and `readdir` methods are signed integers now (breaking change, sorry)
* Link `libosxfuse` on macOS, `libfuse` on all other systems

## 0.3.0 - 2017-01-06

* Fix extended attribute handling (`getxattr` and `listxattr` methods changed and `ReplyXattr` was added)
* `mount` now also returns a `Result` since it may fail if the session fails to run
* Filenames are now passed as `&OsStr` in the filesystem interface
* Removed publishing of documentation on GitHub pages. Docs are now available on https://docs.rs/fuse
* Add `FileType::Socket`

## 0.2.8 - 2016-07-31

* Documentation of releases is build by CI now and made available at https://zargony.github.io/rust-fuse
* Fix `unmount` on BSD systems
* Simplified `libfuse` detection with `pkg-config`
* `ReplyDirectory::sized` was removed since it was impossible to use it safely

## 0.2.7 - 2015-09-08

* Update to latest Rust stable - no longer needs nightly Rust
* A filesystem implementation doesn't need to be `Send` anymore to be mounted synchronously
* A filesystem implementation doesn't need to be 'static anymore to be mounted asynchronously
* CI tests are covering nightly, beta and stable Rust under OSX and Linux now

## 0.2.6 - 2015-04-23

* Update to latest Rust nightly
* Fix mounting of filesystems as non-root on Linux systems

## 0.2.5 - 2015-03-21

* Update to latest Rust nightly
* `unmount` returns a `Result` now since unmounting may fail internally
* Fix `unmount` on Linux systems
* Remove deprecated file types from interface (got rid of `std::old_io`)
* Introducing `FileType`

## 0.2.4 - 2015-02-22

* Update to latest Rust nightly
* `spawn_mount` returns a `Result` now since starting a new thread may fail
* Paths are now passed using `std::path::Path` (got rid of `std::old_path`)
* FUSE options are now passed as a slice of `OsStr` rather than a slice of bytes

## 0.2.3 - 2015-01-17

* Update to latest Rust nightly

## 0.2.2 - 2015-01-14

* Update to latest Rust nightly
* Ensure that `Reply` is `Send` to support asynchronous processing
* Add CI testing under Linux

## 0.2.1 - 2015-01-07

* Update to latest Rust nightly
* Use `build.rs` and `pkg-config` to discover `libfuse` / `libosxfuse`

## 0.2.0 - 2014-12-25

Initial release

## pre-0.2.0 - 2013-10-03

No versioning (based on make, cargo and crates.io didn't exist yet)
