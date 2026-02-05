//! BSD mount tests

use anyhow::Context;
use anyhow::bail;
use tempfile::TempDir;
use tokio::process::Command;

use crate::ansi::green;
use crate::cargo::cargo_build_example;
use crate::command_utils::command_success;
use crate::mount_util::wait_for_fuse_mount;

pub(crate) async fn run_bsd_mount_tests() -> anyhow::Result<()> {
    let mount_dir = TempDir::new().context("Failed to create mount directory")?;
    let mount_path = mount_dir.path().to_str().context("Invalid mount path")?;

    let hello_exe = cargo_build_example("hello", &[]).await?;

    eprintln!("Starting hello filesystem...");
    let mut fuse_process = Command::new(&hello_exe)
        .args([mount_path])
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;

    wait_for_fuse_mount(mount_dir.path()).await?;

    let hello_path = mount_dir.path().join("hello.txt");
    let content = tokio::fs::read_to_string(&hello_path)
        .await
        .context("Failed to read hello.txt")?;

    if content == "Hello World!\n" {
        green!("OK without libfuse");
    } else {
        bail!(
            "hello.txt content mismatch: expected 'Hello World!', got '{}'",
            content
        );
    }

    command_success(["umount", mount_path]).await?;

    fuse_process
        .kill()
        .await
        .context("Failed to kill FUSE process")?;

    green!("All BSD mount tests passed!");
    Ok(())
}
