//! Test runner for fuser

mod ansi;
mod apt;
mod bsd_mount;
mod cargo;
mod command_utils;
mod experimental;
mod features;
mod fuse_conf;
mod fusermount;
mod macos_mount;
mod mount;
mod mount_util;
mod simple;
mod unmount;
mod users;

use anyhow::bail;
use clap::Parser;
use clap::Subcommand;

/// Execute e2e tests for fuser.
#[derive(Parser)]
struct FuserTests {
    #[command(subcommand)]
    command: FuserCommand,
}

#[derive(Subcommand)]
enum FuserCommand {
    /// Run experimental mount tests.
    Experimental,
    /// Run BSD mount tests.
    BsdMount,
    /// Run macOS mount tests.
    MacosMount,
    /// Run mount tests.
    Mount,
    /// Run simple filesystem tests.
    Simple,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::select! {
        result = main_inner() => result,
        x = tokio::signal::ctrl_c() => {
            // Wait for signal so `kill_on_drop` will kill the process.
            x?;
            bail!("Interrupted by Ctrl+C")
        }
    }
}

async fn main_inner() -> anyhow::Result<()> {
    // Validate that we're running inside Docker on Linux.
    if cfg!(target_os = "linux") && std::env::var("FUSER_TESTS_IN_DOCKER").as_deref() != Ok("true")
    {
        bail!(
            "FUSER_TESTS_IN_DOCKER environment variable is not set to 'true'. \
            Tests must be run inside Docker."
        );
    }

    let FuserTests { command } = FuserTests::parse();
    match command {
        FuserCommand::Experimental => experimental::run_experimental_tests().await?,
        FuserCommand::BsdMount => bsd_mount::run_bsd_mount_tests().await?,
        FuserCommand::MacosMount => macos_mount::run_macos_mount_tests().await?,
        FuserCommand::Mount => mount::run_mount_tests().await?,
        FuserCommand::Simple => simple::run_simple_tests().await?,
    }
    Ok(())
}
