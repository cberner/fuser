//! Test runner for fuser

mod ansi;
mod apt;
mod command_utils;
mod mount;
mod simple;

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
    let FuserTests { command } = FuserTests::parse();
    match command {
        FuserCommand::Mount => mount::run_mount_tests().await?,
        FuserCommand::Simple => simple::run_simple_tests().await?,
    }
    Ok(())
}
