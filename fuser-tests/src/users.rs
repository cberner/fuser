//! User management utilities

use anyhow::Context;
use tokio::process::Command;

use crate::command_utils::command_success;

pub(crate) async fn useradd(username: &str) -> anyhow::Result<()> {
    command_success(["useradd", username]).await
}

pub(crate) async fn run_as_user(username: &str, command: &str) -> anyhow::Result<String> {
    let output = Command::new("su")
        .args([username, "-c", command])
        .output()
        .await
        .context(format!("Failed to run command as user {}", username))?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) async fn run_as_user_status(username: &str, command: &str) -> anyhow::Result<i32> {
    let status = Command::new("su")
        .args([username, "-c", command])
        .status()
        .await
        .context(format!("Failed to run command as user {}", username))?;

    Ok(status.code().unwrap_or(-1))
}
