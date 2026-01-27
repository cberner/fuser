//! Test runner for fuser

mod simple;

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
    /// Run simple filesystem tests.
    Simple,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let FuserTests { command } = FuserTests::parse();
    match command {
        FuserCommand::Simple => simple::run_simple_tests().await?,
    }
    Ok(())
}
