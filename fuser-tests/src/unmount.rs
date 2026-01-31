use anyhow::Context;
use anyhow::bail;
use tokio::process::Child;

use crate::ansi::green;
use crate::command_utils::command_success;
use crate::mount_util::read_mounts;
use crate::mount_util::wait_for_fuse_umount;

/// Unmount behavior for FUSE filesystem tests.
pub(crate) enum Unmount {
    /// Use `--auto-unmount` flag, filesystem unmounts automatically when process exits.
    Auto,
    /// Manual unmount required after process exits.
    Manual,
}

/// Kill the FUSE process and handle unmounting based on the unmount mode.
pub(crate) async fn kill_and_unmount(
    mut fuse_process: Child,
    unmount: Unmount,
    device: &str,
    mount_path: &str,
    description: &str,
) -> anyhow::Result<()> {
    // Check that mount exists before killing the process
    let entries = read_mounts().await?;
    if !entries.iter().any(|e| e.is_fuse_mount_on_dev(device)) {
        bail!("FUSE mount does not exist before kill");
    }

    fuse_process
        .kill()
        .await
        .context("Failed to kill FUSE process")?;

    match unmount {
        Unmount::Auto => {
            wait_for_fuse_umount(device).await?;
            green!("OK Mount cleaned up: {} --auto-unmount", description);
        }
        Unmount::Manual => {
            command_success(["umount", mount_path]).await?;
            green!("OK Unmounted: {}", description);
        }
    }

    Ok(())
}
