use fuser::{Filesystem, MountOption};
use std::env;

struct NullFS;

impl Filesystem for NullFS {}

fn main() {
    env_logger::init();
    let mountpoint = env::args_os().nth(1).unwrap();
    let (chan, _mount) = fuser::mount3(mountpoint, &[MountOption::AutoUnmount]).unwrap();
    fuser::serve_fs_sync_forever(&chan.init().unwrap(), NullFS).unwrap();
}
