//! Main mount tests

use std::convert::Infallible;
use std::fmt::Write;
use std::io;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::bail;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::task::JoinError;
use tokio::task::JoinSet;

use crate::ansi::green;
use crate::cargo::cargo_build_example;
use crate::command_utils::command_output;
use crate::experimental::run_experimental_tests;
use crate::features::Feature;
use crate::features::features_to_flags;
use crate::fuse_conf::fuse_conf_remove_user_allow_other;
use crate::fuse_conf::fuse_conf_write_user_allow_other;
use crate::fusermount::Fusermount;
use crate::libfuse::Libfuse;
use crate::mount_util::wait_for_fuse_mount;
use crate::unmount::Unmount;
use crate::unmount::kill_and_unmount;
use crate::users::assert_can_read_as_user;
use crate::users::assert_cannot_read_as_user;
use crate::users::mktempdir_as_user;
use crate::users::run_as_user_status;

pub(crate) async fn run_mount_tests(libfuse: Libfuse) -> anyhow::Result<()> {
    run_mount_tests_inner(libfuse)
        .await
        .with_context(|| format!("Tests with {libfuse} failed"))
}

async fn run_mount_tests_inner(libfuse: Libfuse) -> anyhow::Result<()> {
    fuse_conf_write_user_allow_other().await?;

    // Tests without libfuse feature (pure Rust implementation)
    run_test(&[], Unmount::Manual, Fusermount::False, 1).await?;
    run_test(&[], Unmount::Auto, libfuse.fusermount(), 1).await?;
    test_no_user_allow_other(&[], &libfuse).await?;

    // Tests with libfuse
    run_test(&[libfuse.feature()], Unmount::Manual, Fusermount::False, 1).await?;
    run_test(&[libfuse.feature()], Unmount::Auto, libfuse.fusermount(), 1).await?;

    // Multi-threaded tests
    run_test(&[], Unmount::Auto, libfuse.fusermount(), 2).await?;

    if let Libfuse::Libfuse3 = libfuse {
        run_allow_root_test()
            .await
            .context("allow_root tests failed")?;
    }

    green!("All mount tests passed!");

    run_experimental_tests(libfuse)
        .await
        .context("experimental mount tests failed")?;

    Ok(())
}

async fn run_test(
    features: &[Feature],
    unmount: Unmount,
    fusermount: Fusermount,
    n_threads: usize,
) -> anyhow::Result<()> {
    let mut description = String::new();
    match features_to_flags(features) {
        Some(flags) => description.push_str(&flags),
        None => description.push_str("default features"),
    }
    write!(description, " fusermount={fusermount}").unwrap();
    match unmount {
        Unmount::Auto => description.push_str(" --auto-unmount"),
        Unmount::Manual => {}
    }
    write!(description, " n_threads={n_threads}").unwrap();

    run_test_inner(features, unmount, fusermount, n_threads, &description)
        .await
        .with_context(|| format!("Tests failed: {description}"))
}

async fn run_test_inner(
    features: &[Feature],
    unmount: Unmount,
    fusermount: Fusermount,
    n_threads: usize,
    description: &str,
) -> anyhow::Result<()> {
    eprintln!("\n=== Running test: {description} ===");

    let mount_dir = TempDir::new().context("Failed to create mount directory")?;
    let mount_path = mount_dir.path().to_str().unwrap();

    eprintln!("Mount dir: {}", mount_path);

    let hello_exe = cargo_build_example("hello", features).await?;

    // Run the hello example
    eprintln!("Starting hello filesystem...");
    let n_threads_str = n_threads.to_string();
    let mut run_args = vec![mount_path, "--n-threads", &n_threads_str];
    if matches!(unmount, Unmount::Auto) {
        run_args.push("--auto-unmount");
    }

    let fuse_process = Command::new(&hello_exe)
        .args(&run_args)
        .env(Fusermount::ENV_VAR, fusermount.as_path())
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;

    wait_for_fuse_mount("hello").await?;

    // Read hello.txt
    let hello_path = mount_dir.path().join("hello.txt");
    let content = tokio::fs::read_to_string(&hello_path)
        .await
        .context("Failed to read hello.txt")?;

    if content == "Hello World!\n" {
        green!("OK {description}");
    } else {
        bail!(
            "hello.txt content mismatch: expected 'Hello World!', got '{}'",
            content
        );
    }

    // Check all threads handle requests.
    if n_threads != 1 {
        let mut tasks = JoinSet::new();
        for _ in 0..20 {
            let hello_path = hello_path.clone();
            tasks.spawn(async move {
                loop {
                    tokio::fs::read_to_string(&hello_path).await?;
                }
            });
        }

        let stats_per_thread = mount_dir.path().join("stats-per-thread");

        let start = Instant::now();

        let stats_per_thread = loop {
            let stats_per_thread = tokio::fs::read_to_string(&stats_per_thread).await?;
            let stats_per_thread: Vec<u64> = stats_per_thread
                .lines()
                .map(|l| l.parse().context("Failed to parse stats line"))
                .collect::<anyhow::Result<_>>()?;
            anyhow::ensure!(stats_per_thread.len() == n_threads);
            if stats_per_thread.iter().all(|t| *t > 0) {
                break stats_per_thread;
            }

            if start.elapsed() > Duration::from_secs(5) {
                bail!("Not all threads handled requests in 5s; current stats: {stats_per_thread:?}")
            }

            match tasks.try_join_next() {
                None => continue,
                Some(Err::<_, JoinError>(e)) => return Err(e).context("Failed to join task"),
                Some(Ok(Err::<_, io::Error>(e))) => return Err(e).context("Reader thread failed"),
                Some(Ok(Ok::<Infallible, _>(x))) => match x {},
            }
        };

        green!("OK multi-threaded tests passed: {stats_per_thread:?}");
    }

    kill_and_unmount(fuse_process, unmount, "hello", mount_path).await?;

    green!("OK {description}");

    Ok(())
}

async fn test_no_user_allow_other(features: &[Feature], libfuse: &Libfuse) -> anyhow::Result<()> {
    let description = if features.is_empty() {
        format!("without libfuse, with {}", libfuse.fusermount())
    } else {
        features
            .iter()
            .map(|f| format!("with {}", f))
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!(
        "\n=== Running test_no_user_allow_other: {} ===",
        description
    );

    fuse_conf_remove_user_allow_other().await?;

    let mount_dir = mktempdir_as_user("fusertestnoallow").await?;
    let data_dir = mktempdir_as_user("fusertestnoallow").await?;

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

    let mount_dir = mktempdir_as_user("fusertest1").await?;
    eprintln!("Mount dir: {}", mount_dir);

    let hello_exe = cargo_build_example("hello", &[Feature::Libfuse3]).await?;

    // Run the hello example as fusertest1 with --allow-root
    let run_command = format!("{} {} --allow-root", hello_exe.display(), mount_dir);
    let fuse_process = Command::new("su")
        .args(["fusertest1", "-c", &run_command])
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start hello example")?;

    wait_for_fuse_mount("hello").await?;

    // Test: root can read
    let hello_path = format!("{}/hello.txt", mount_dir);
    assert_can_read_as_user("root", &hello_path, "Hello World!\n").await?;
    green!("OK root can read");

    // Test: owner can read
    assert_can_read_as_user("fusertest1", &hello_path, "Hello World!\n").await?;
    green!("OK owner can read");

    // Test: other user can't read
    assert_cannot_read_as_user("fusertest2", &hello_path).await?;
    green!("OK other user can't read");

    kill_and_unmount(fuse_process, Unmount::Manual, "hello", &mount_dir).await?;

    green!("OK run_allow_root_test");

    Ok(())
}
