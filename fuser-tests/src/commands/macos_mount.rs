//! macOS mount tests

use anyhow::Context;
use anyhow::bail;
use tempfile::TempDir;
use tokio::process::Child;
use tokio::process::Command;

use crate::ansi::green;
use crate::cargo::cargo_build_example;
use crate::command_utils::command_success;
use crate::mount_util::wait_for_fuse_mount;

pub(crate) async fn run_macos_mount_tests() -> anyhow::Result<()> {
    let mount_path = TempDir::new().context("Failed to create mount directory")?;
    // Must canonicalize to check `mount` output.
    let mount_path = mount_path.path().canonicalize()?;

    let hello_exe = cargo_build_example("hello", &[]).await?;

    eprintln!("Starting hello filesystem...");
    let mut fuse_process = Command::new(&hello_exe)
        .args([&mount_path])
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;

    wait_for_fuse_mount(&mount_path).await?;

    let hello_path = mount_path.join("hello.txt");
    let content = tokio::fs::read_to_string(&hello_path)
        .await
        .context("Failed to read hello.txt")?;

    if content == "Hello World!\n" {
        green!("OK with macFUSE");
    } else {
        bail!(
            "hello.txt content mismatch: expected 'Hello World!', got '{}'",
            content
        );
    }

    command_success(["umount", mount_path.to_str().unwrap()]).await?;
    ensure_process_stopped(&mut fuse_process).await?;

    green!("All macOS mount tests passed!");
    Ok(())
}

async fn ensure_process_stopped(process: &mut Child) -> anyhow::Result<()> {
    if process
        .try_wait()
        .context("Failed to check FUSE process status")?
        .is_some()
    {
        return Ok(());
    }

    match process.kill().await {
        Ok(()) => {
            let _ = process
                .wait()
                .await
                .context("Failed to wait for FUSE process after kill")?;
        }
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound
            ) =>
        {
            // Process already exited after unmount.
        }
        Err(err) => {
            return Err(err).context("Failed to kill FUSE process");
        }
    }

    Ok(())
}
