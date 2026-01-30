//! Experimental mount tests

use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::bail;
use tempfile::TempDir;
use tokio::process::Command;

use crate::ansi::green;
use crate::apt::apt_install;
use crate::apt::apt_remove;
use crate::apt::apt_update;
use crate::cargo::cargo_build_example;
use crate::command_utils::command_output;
use crate::command_utils::command_success;
use crate::features::Feature;
use crate::fuse_conf::fuse_conf_remove_user_allow_other;
use crate::fuse_conf::fuse_conf_write_user_allow_other;
use crate::fusermount::Fusermount;
use crate::unmount::Unmount;
use crate::users::run_as_user;
use crate::users::run_as_user_status;

pub(crate) async fn run_experimental_tests() -> anyhow::Result<()> {
    apt_update().await?;
    apt_install(&["fuse"]).await?;
    fuse_conf_write_user_allow_other().await?;

    run_test(
        &[Feature::Experimental],
        "without libfuse, with fusermount",
        Unmount::Manual,
        Fusermount::False,
    )
    .await?;
    run_test(
        &[Feature::Experimental],
        "without libfuse, with fusermount",
        Unmount::Auto,
        Fusermount::Fusermount,
    )
    .await?;
    test_no_user_allow_other(&[], "without libfuse, with fusermount").await?;

    apt_remove(&["fuse"]).await?;
    apt_install(&["fuse3"]).await?;
    fuse_conf_write_user_allow_other().await?;

    run_test(
        &[Feature::Experimental],
        "without libfuse, with fusermount3",
        Unmount::Manual,
        Fusermount::False,
    )
    .await?;
    run_test(
        &[Feature::Experimental],
        "without libfuse, with fusermount3",
        Unmount::Auto,
        Fusermount::Fusermount3,
    )
    .await?;
    test_no_user_allow_other(&[], "without libfuse, with fusermount3").await?;

    apt_remove(&["fuse3"]).await?;
    apt_install(&["libfuse-dev", "pkg-config", "fuse"]).await?;
    fuse_conf_write_user_allow_other().await?;

    run_test(
        &[Feature::Libfuse2, Feature::Experimental],
        "with libfuse",
        Unmount::Manual,
        Fusermount::False,
    )
    .await?;
    run_test(
        &[Feature::Libfuse2, Feature::Experimental],
        "with libfuse",
        Unmount::Auto,
        Fusermount::Fusermount,
    )
    .await?;

    apt_remove(&["libfuse-dev", "fuse"]).await?;
    apt_install(&["libfuse3-dev", "fuse3"]).await?;
    fuse_conf_write_user_allow_other().await?;

    run_test(
        &[Feature::Libfuse3, Feature::Experimental],
        "with libfuse3",
        Unmount::Manual,
        Fusermount::False,
    )
    .await?;
    run_test(
        &[Feature::Libfuse3, Feature::Experimental],
        "with libfuse3",
        Unmount::Auto,
        Fusermount::Fusermount3,
    )
    .await?;

    run_allow_root_test().await?;

    green!("All experimental mount tests passed!");
    Ok(())
}

async fn run_test(
    features: &[Feature],
    description: &str,
    unmount: Unmount,
    fusermount: Fusermount,
) -> anyhow::Result<()> {
    let unmount_desc = match unmount {
        Unmount::Auto => "--auto-unmount",
        Unmount::Manual => "",
    };
    eprintln!("\n=== Running test: {} {} ===", description, unmount_desc);

    let mount_dir = TempDir::new().context("Failed to create mount directory")?;
    let mount_path = mount_dir.path().to_str().unwrap();

    eprintln!("Mount dir: {}", mount_path);

    let async_hello_exe = cargo_build_example("async_hello", features).await?;

    // Run the async_hello example
    eprintln!("Starting async_hello filesystem...");
    let mut run_args = vec![mount_path];
    if matches!(unmount, Unmount::Auto) {
        run_args.push("--auto-unmount");
    }

    let mut fuse_process = Command::new(&async_hello_exe)
        .args(&run_args)
        .env(Fusermount::ENV_VAR, fusermount.as_path())
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start async_hello example")?;

    // Wait for mount to be ready
    eprintln!("Waiting for mount...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    eprintln!("mounting at {}", mount_path);

    // Check if FUSE was successfully mounted
    let mount_info = command_output(["mount"]).await?;
    if !mount_info.contains("hello") {
        bail!("FUSE mount not found in mount output");
    }

    // Read hello.txt
    let hello_path = mount_dir.path().join("hello.txt");
    let content = tokio::fs::read_to_string(&hello_path)
        .await
        .context("Failed to read hello.txt")?;

    if content == "Hello World!\n" {
        green!("OK {} {}", description, unmount_desc);
    } else {
        bail!(
            "hello.txt content mismatch: expected 'Hello World!', got '{}'",
            content
        );
    }

    // Kill the FUSE process
    fuse_process
        .kill()
        .await
        .context("Failed to kill FUSE process")?;

    match unmount {
        Unmount::Auto => {
            let start = Instant::now();
            loop {
                // Make sure the FUSE mount automatically unmounted
                let mount_info = command_output(["mount"]).await?;
                if mount_info.contains("hello") {
                    if start.elapsed() > Duration::from_secs(3) {
                        bail!(
                            "Mount not cleaned up after auto-unmount: {} {}",
                            description,
                            unmount_desc
                        );
                    }
                    eprintln!("Mount not cleared yet, waiting...");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                } else {
                    green!("OK Mount cleaned up: {} {}", description, unmount_desc);
                    break;
                }
            }
        }
        Unmount::Manual => {
            // Unmount manually
            command_success(["umount", mount_path]).await?;
        }
    }

    Ok(())
}

async fn test_no_user_allow_other(features: &[Feature], description: &str) -> anyhow::Result<()> {
    eprintln!(
        "\n=== Running test_no_user_allow_other: {} ===",
        description
    );

    fuse_conf_remove_user_allow_other().await?;

    let mount_dir = run_as_user("fusertestnoallow", "mktemp --directory").await?;
    let data_dir = run_as_user("fusertestnoallow", "mktemp --directory").await?;

    eprintln!("Mount dir: {}", mount_dir);
    eprintln!("Data dir: {}", data_dir);

    let simple_exe = cargo_build_example("simple", features).await?;

    // Run the simple example as fusertestnoallow
    let run_command = format!(
        "{} --auto-unmount -vvv --data-dir {} --mount-point {}",
        simple_exe.display(),
        data_dir,
        mount_dir
    );

    let exit_code = run_as_user_status("fusertestnoallow", &run_command).await?;

    if exit_code == 2 {
        green!("OK Detected lack of user_allow_other: {}", description);
    } else {
        bail!("Expected exit code 2, got {}", exit_code);
    }

    // Make sure the FUSE mount did not mount
    let mount_info = command_output(["mount"]).await?;
    if mount_info.contains("hello") {
        let _ = Command::new("umount").arg(&mount_dir).status().await;
        bail!("Mount should not exist");
    } else {
        green!("OK Mount does not exist: {}", description);
    }

    // Restore fuse.conf
    fuse_conf_write_user_allow_other().await?;

    Ok(())
}

async fn run_allow_root_test() -> anyhow::Result<()> {
    eprintln!("\n=== Running run_allow_root_test ===");

    let mount_dir = run_as_user("fusertest1", "mktemp --directory").await?;
    eprintln!("Mount dir: {}", mount_dir);

    let async_hello_exe =
        cargo_build_example("async_hello", &[Feature::Libfuse3, Feature::Experimental]).await?;

    // Run the async_hello example as fusertest1 with --allow-root
    let run_command = format!("{} {} --allow-root", async_hello_exe.display(), mount_dir);
    let mut fuse_process = Command::new("su")
        .args(["fusertest1", "-c", &run_command])
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start async_hello example")?;

    // Wait for mount to be ready
    eprintln!("Waiting for mount...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    eprintln!("mounting at {}", mount_dir);

    // Check if FUSE was successfully mounted
    let mount_info = command_output(["mount"]).await?;
    if !mount_info.contains("hello") {
        bail!("FUSE mount not found in mount output");
    }

    // Test: root can read
    let hello_path = format!("{}/hello.txt", mount_dir);
    let root_content = run_as_user("root", &format!("cat {}", hello_path)).await?;
    if root_content == "Hello World!" {
        green!("OK root can read");
    } else {
        bail!("root can't read hello.txt");
    }

    // Test: owner can read
    let owner_content = run_as_user("fusertest1", &format!("cat {}", hello_path)).await?;
    if owner_content == "Hello World!" {
        green!("OK owner can read");
    } else {
        bail!("owner can't read hello.txt");
    }

    // Test: other user can't read
    let other_content = run_as_user("fusertest2", &format!("cat {}", hello_path)).await?;
    if other_content == "Hello World!" {
        bail!("other user should not be able to read hello.txt");
    } else {
        green!("OK other user can't read");
    }

    // Kill the FUSE process
    fuse_process
        .kill()
        .await
        .context("Failed to kill FUSE process")?;

    Ok(())
}
