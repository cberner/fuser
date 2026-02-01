use std::path::PathBuf;

use clap::Parser;
use fuser::Config;
use fuser::Filesystem;
use fuser::MountOption;
use fuser::SessionACL;

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
    let mut cfg = Config::default();
    cfg.mount_options = vec![MountOption::AutoUnmount];
    cfg.acl = SessionACL::All;
    fuser::mount2(NullFS, &args.mount_point, &cfg).unwrap();
}
