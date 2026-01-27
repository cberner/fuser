//! Simple filesystem tests

use std::time::Duration;

use anyhow::Context;
use anyhow::bail;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::process::Command;

pub(crate) async fn run_simple_tests() -> anyhow::Result<()> {
    tokio::select! {
        result = run_simple_tests_impl() => result,
        x = tokio::signal::ctrl_c() => {
            // Wait for signal so `kill_on_drop` will kill the process.
            x?;
            bail!("Interrupted by Ctrl+C")
        }
    }
}

async fn run_simple_tests_impl() -> anyhow::Result<()> {
    // Create temp directories
    let data_dir = TempDir::new().context("Failed to create data directory")?;
    let mount_dir = TempDir::new().context("Failed to create mount directory")?;

    eprintln!("Data dir: {:?}", data_dir.path());
    eprintln!("Mount dir: {:?}", mount_dir.path());

    // Build the simple example
    eprintln!("Building simple example...");
    let build_status = Command::new("cargo")
        .args(["build", "--example", "simple"])
        .status()
        .await
        .context("Failed to run cargo build")?;

    if !build_status.success() {
        bail!("Failed to build simple example");
    }

    // Run the simple example
    eprintln!("Starting simple filesystem...");
    let mut fuse_process = Command::new("cargo")
        .args([
            "run",
            "--example",
            "simple",
            "--",
            "-vvv",
            "--data-dir",
            data_dir.path().to_str().unwrap(),
            "--mount-point",
            mount_dir.path().to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start simple example")?;

    // Wait for mount to be ready
    eprintln!("Waiting for mount...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check if FUSE was successfully mounted
    let mount_output = Command::new("mount")
        .output()
        .await
        .context("Failed to run mount command")?;

    let mount_info = String::from_utf8_lossy(&mount_output.stdout);
    if !mount_info.contains("fuser") {
        bail!("FUSE mount not found in mount output");
    }
    eprintln!("Mount verified successfully");

    // Test: touch files
    eprintln!("Testing touch file operations...");
    let file_a = mount_dir.path().join("a");
    let file_b = mount_dir.path().join("b");

    File::create(&file_a)
        .await
        .context("Failed to touch file 'a'")?;
    File::create(&file_b)
        .await
        .context("Failed to touch file 'b'")?;
    eprintln!("OK touch file");

    // Unmount
    eprintln!("Unmounting...");
    let umount_status = Command::new("umount")
        .arg(mount_dir.path())
        .status()
        .await
        .context("Failed to run umount")?;

    if !umount_status.success() {
        bail!("Failed to unmount");
    }

    // Kill the FUSE process
    fuse_process
        .kill()
        .await
        .context("Failed to kill FUSE process")?;

    eprintln!("All simple tests passed!");
    Ok(())
}
