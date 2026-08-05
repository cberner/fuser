use bitflags::bitflags;

bitflags! {
    /// Which fields of a `statx` reply are filled in, as `struct statx`'s `stx_mask`.
    ///
    /// A filesystem does not choose these: they follow from what it answered with, and
    /// [`crate::StatxAttr`] derives them. The caller's own request is a separate mask, which
    /// reaches [`crate::Filesystem::statx`] as `mask`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct StatxMask: u32 {
        /// `stx_mode` & `S_IFMT` is filled in.
        const TYPE = 1 << 0;
        /// `stx_mode` & `!S_IFMT` is filled in.
        const MODE = 1 << 1;
        /// `stx_nlink` is filled in.
        const NLINK = 1 << 2;
        /// `stx_uid` is filled in.
        const UID = 1 << 3;
        /// `stx_gid` is filled in.
        const GID = 1 << 4;
        /// `stx_atime` is filled in.
        const ATIME = 1 << 5;
        /// `stx_mtime` is filled in.
        const MTIME = 1 << 6;
        /// `stx_ctime` is filled in.
        const CTIME = 1 << 7;
        /// `stx_ino` is filled in.
        const INO = 1 << 8;
        /// `stx_size` is filled in.
        const SIZE = 1 << 9;
        /// `stx_blocks` is filled in.
        const BLOCKS = 1 << 10;
        /// Everything a plain `stat(2)` also reports.
        const BASIC_STATS = 0x0000_07ff;
        /// `stx_btime` is filled in.
        const BTIME = 1 << 11;
    }
}

bitflags! {
    /// Properties of a file that `statx(2)` reports beyond `stat(2)`, as `stx_attributes`.
    ///
    /// The kernel has no way to learn these from a FUSE filesystem other than being told: it
    /// fills `stx_attributes` from its own inode flags, which a FUSE filesystem's flags are
    /// not. Answering `FUSE_STATX` is what makes `chattr +i` and friends visible to
    /// `statx(2)`.
    ///
    /// Whatever is reported here counts only where the matching bit is also set in
    /// [`crate::StatxAttr::attributes_mask`], which is how a caller tells "not set" from
    /// "not supported".
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct StatxAttributes: u64 {
        /// The file is compressed by the filesystem.
        const COMPRESSED = 1 << 2;
        /// The file is marked immutable, as `chattr +i` sets.
        const IMMUTABLE = 1 << 4;
        /// The file is append-only, as `chattr +a` sets.
        const APPEND = 1 << 5;
        /// The file is not to be dumped, as `chattr +d` sets.
        const NODUMP = 1 << 6;
        /// The file needs a key to be decrypted by the filesystem.
        const ENCRYPTED = 1 << 11;
        /// The directory is an automount trigger.
        const AUTOMOUNT = 1 << 12;
        /// The entry is the root of a mount.
        const MOUNT_ROOT = 1 << 13;
        /// The file is protected by fs-verity.
        const VERITY = 1 << 20;
        /// The file is in the DAX state, mapped directly from persistent memory.
        const DAX = 1 << 21;
    }
}
