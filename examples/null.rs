use std::path::PathBuf;

use clap::Parser;
use fuser::Filesystem;
use fuser::MountOption;

#[derive(Parser)]
#[command(version)]
struct Args {
    /// Act as a client, and mount FUSE at given path
    mount_point: PathBuf,
}

struct NullFS;

impl Filesystem for NullFS {}

fn main() {
    let args = Args::parse();
    env_logger::init();
    fuser::mount2(
        NullFS,
        &args.mount_point,
        &[MountOption::AutoUnmount, MountOption::AllowOther],
    )
    .unwrap();
}
