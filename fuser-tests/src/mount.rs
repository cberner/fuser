//! Main mount tests

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
use crate::command_utils::command_output;
use crate::command_utils::command_success;

/// Unmount behavior for FUSE filesystem tests.
enum Unmount {
    /// Use `--auto-unmount` flag, filesystem unmounts automatically when process exits.
    Auto,
    /// Manual unmount required after process exits.
    Manual,
}

pub(crate) async fn run_mount_tests() -> anyhow::Result<()> {
    apt_update().await?;
    apt_install(&["fuse"]).await?;
    write_user_allow_other().await?;

    run_test("", "without libfuse, with fusermount", Unmount::Manual).await?;
    run_test("", "without libfuse, with fusermount", Unmount::Auto).await?;
    test_no_user_allow_other("", "without libfuse, with fusermount").await?;

    apt_remove(&["fuse"]).await?;
    apt_install(&["fuse3"]).await?;
    write_user_allow_other().await?;

    run_test("", "without libfuse, with fusermount3", Unmount::Manual).await?;
    run_test("", "without libfuse, with fusermount3", Unmount::Auto).await?;
    test_no_user_allow_other("", "without libfuse, with fusermount3").await?;

    apt_remove(&["fuse3"]).await?;
    apt_install(&["libfuse-dev", "pkg-config", "fuse"]).await?;
    write_user_allow_other().await?;

    run_test("libfuse", "with libfuse", Unmount::Manual).await?;
    run_test("libfuse", "with libfuse", Unmount::Auto).await?;

    apt_remove(&["libfuse-dev", "fuse"]).await?;
    apt_install(&["libfuse3-dev", "fuse3"]).await?;
    write_user_allow_other().await?;

    run_test("libfuse,abi-7-30", "with libfuse3", Unmount::Manual).await?;
    run_test("libfuse,abi-7-30", "with libfuse3", Unmount::Auto).await?;

    run_allow_root_test().await?;

    green!("All mount tests passed!");
    Ok(())
}

async fn write_user_allow_other() -> anyhow::Result<()> {
    command_success(["sh", "-c", "echo 'user_allow_other' >> /etc/fuse.conf"]).await
}

async fn remove_user_allow_other() -> anyhow::Result<()> {
    command_success(["sed", "-i", "/user_allow_other/d", "/etc/fuse.conf"]).await
}

async fn useradd(username: &str) -> anyhow::Result<()> {
    eprintln!("Creating user: {}", username);
    let status = Command::new("useradd")
        .arg(username)
        .status()
        .await
        .context(format!("Failed to create user {}", username))?;

    // Ignore failure if user already exists
    if !status.success() {
        eprintln!(
            "Warning: useradd {} may have failed (user might already exist)",
            username
        );
    }
    Ok(())
}

async fn run_as_user(username: &str, command: &str) -> anyhow::Result<String> {
    let output = Command::new("su")
        .args([username, "-c", command])
        .output()
        .await
        .context(format!("Failed to run command as user {}", username))?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn run_as_user_status(username: &str, command: &str) -> anyhow::Result<i32> {
    let status = Command::new("su")
        .args([username, "-c", command])
        .status()
        .await
        .context(format!("Failed to run command as user {}", username))?;

    Ok(status.code().unwrap_or(-1))
}

async fn run_test(features: &str, description: &str, unmount: Unmount) -> anyhow::Result<()> {
    let unmount_desc = match unmount {
        Unmount::Auto => "--auto-unmount",
        Unmount::Manual => "",
    };
    eprintln!("\n=== Running test: {} {} ===", description, unmount_desc);

    let mount_dir = TempDir::new().context("Failed to create mount directory")?;
    let mount_path = mount_dir.path().to_str().unwrap();

    eprintln!("Mount dir: {}", mount_path);

    // Build the hello example
    eprintln!("Building hello example...");
    let mut build_args = vec!["cargo", "build", "--example", "hello"];
    if !features.is_empty() {
        build_args.push("--features");
        build_args.push(features);
    }
    command_success(build_args).await?;

    // Run the hello example
    eprintln!("Starting hello filesystem...");
    let mut run_args = vec!["run", "--example", "hello"];
    if !features.is_empty() {
        run_args.push("--features");
        run_args.push(features);
    }
    run_args.push("--");
    run_args.push(mount_path);
    if matches!(unmount, Unmount::Auto) {
        run_args.push("--auto-unmount");
    }

    let mut fuse_process = Command::new("cargo")
        .args(&run_args)
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;

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

async fn test_no_user_allow_other(features: &str, description: &str) -> anyhow::Result<()> {
    eprintln!(
        "\n=== Running test_no_user_allow_other: {} ===",
        description
    );

    remove_user_allow_other().await?;

    useradd("fusertestnoallow").await?;

    let mount_dir = run_as_user("fusertestnoallow", "mktemp --directory").await?;
    let data_dir = run_as_user("fusertestnoallow", "mktemp --directory").await?;

    eprintln!("Mount dir: {}", mount_dir);
    eprintln!("Data dir: {}", data_dir);

    // Build the simple example
    eprintln!("Building simple example...");
    let mut build_args = vec!["cargo", "build", "--example", "simple"];
    if !features.is_empty() {
        build_args.push("--features");
        build_args.push(features);
    }
    command_success(build_args).await?;

    // Run the simple example as fusertestnoallow
    let run_command = format!(
        "target/debug/examples/simple --auto-unmount -vvv --data-dir {} --mount-point {}",
        data_dir, mount_dir
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
    write_user_allow_other().await?;

    Ok(())
}

async fn run_allow_root_test() -> anyhow::Result<()> {
    eprintln!("\n=== Running run_allow_root_test ===");

    useradd("fusertest1").await?;
    useradd("fusertest2").await?;

    let mount_dir = run_as_user("fusertest1", "mktemp --directory").await?;
    eprintln!("Mount dir: {}", mount_dir);

    // Build the hello example with libfuse and abi-7-30
    eprintln!("Building hello example with libfuse,abi-7-30...");
    command_success([
        "cargo",
        "build",
        "--example",
        "hello",
        "--features",
        "libfuse,abi-7-30",
    ])
    .await?;

    // Run the hello example as fusertest1 with --allow-root
    let run_command = format!("target/debug/examples/hello {} --allow-root", mount_dir);
    let mut fuse_process = Command::new("su")
        .args(["fusertest1", "-c", &run_command])
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;

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
