/// Unmount behavior for FUSE filesystem tests.
pub(crate) enum Unmount {
    /// Use `--auto-unmount` flag, filesystem unmounts automatically when process exits.
    Auto,
    /// Manual unmount required after process exits.
    Manual,
}
