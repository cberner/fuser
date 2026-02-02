use std::path::PathBuf;

use fuser::Config;
use fuser::MountOption;
use fuser::SessionACL;

#[derive(clap::Parser)]
pub struct CommonArgs {
    pub mount_point: PathBuf,

    /// Automatically unmount on process exit
    #[clap(long)]
    pub auto_unmount: bool,

    /// Allow root user to access filesystem
    #[clap(long)]
    pub allow_root: bool,
}

impl CommonArgs {
    pub fn config(&self) -> Config {
        let mut config = Config::default();
        if self.auto_unmount {
            config.mount_options.push(MountOption::AutoUnmount);
        }
        if self.allow_root {
            config.acl = SessionACL::RootAndOwner;
        }
        if config.mount_options.contains(&MountOption::AutoUnmount)
            && config.acl != SessionACL::RootAndOwner
        {
            config.acl = SessionACL::All;
        }
        config
    }
}
