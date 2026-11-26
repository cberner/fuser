//! macOS mount tests

use anyhow::Context;
use anyhow::bail;
use tokio::process::Command;

use crate::ansi::green;
use crate::canonical_temp_dir::CanonicalTempDir;
use crate::cargo::cargo_build_example;
use crate::command_utils::command_success;
use crate::features::Feature;
use crate::mount_util::wait_for_fuse_mount;

pub(crate) async fn run_macos_mount_tests() -> anyhow::Result<()> {
    let mount_dir = CanonicalTempDir::new()?;
    let mount_path = mount_dir.path();

    // FUSER_MACOS_SMB=1 to test the SMB backend, which needs no macFUSE
    let smb = std::env::var_os("FUSER_MACOS_SMB").is_some();
    let features: &[Feature] = if smb { &[Feature::MacosSmb] } else { &[] };
    let hello_exe = cargo_build_example("hello", features).await?;

    eprintln!("Starting hello filesystem...");
    // e.g. "backend=fskit" to test macFUSE's FSKit backend
    let extra_option = std::env::var("FUSER_MOUNT_OPTION").ok();
    let mut fuse_process = Command::new(&hello_exe)
        .args(extra_option.iter().flat_map(|o| ["-o", o.as_str()]))
        .arg(mount_path)
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;

    wait_for_fuse_mount(&mount_path).await?;

    let hello_path = mount_path.join("hello.txt");
    let content = tokio::fs::read_to_string(&hello_path)
        .await
        .context("Failed to read hello.txt")?;

    if content == "Hello World!\n" {
        if smb {
            green!("OK with mount_smbfs");
        } else {
            green!("OK with macFUSE");
        }
    } else {
        bail!(
            "hello.txt content mismatch: expected 'Hello World!', got '{}'",
            content
        );
    }

    command_success(["umount", mount_path.to_str().unwrap()]).await?;

    fuse_process
        .kill()
        .await
        .context("Failed to kill/wait FUSE process")?;

    green!("All macOS mount tests passed!");
    Ok(())
}
