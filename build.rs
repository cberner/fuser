fn main() {
    // Register rustc cfg for switching between mount implementations.
    println!(
        "cargo::rustc-check-cfg=cfg(fuser_mount_impl, values(\"pure-rust\", \"libfuse2\", \"libfuse3\", \"macos-no-mount\", \"nfs\"))"
    );
    // macFUSE's FSKit backend, mounted through its MFMount framework
    println!("cargo::rustc-check-cfg=cfg(fuser_macfuse_fskit)");
    // For tests with other NFS clients: the NFS backend's server on any OS, which mounts nothing
    println!("cargo::rustc-check-cfg=cfg(fuser_nfs_serve_only)");
    println!("cargo::rerun-if-env-changed=FUSER_NFS_SERVE_ONLY");
    if std::env::var_os("FUSER_NFS_SERVE_ONLY").is_some() {
        println!("cargo::rustc-cfg=fuser_mount_impl=\"nfs\"");
        println!("cargo::rustc-cfg=fuser_nfs_serve_only");
        return;
    }

    let target_os =
        std::env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS should be set");

    if matches!(
        target_os.as_str(),
        "linux" | "android" | "freebsd" | "dragonfly" | "openbsd" | "netbsd"
    ) && cfg!(not(feature = "libfuse"))
    {
        println!("cargo::rustc-cfg=fuser_mount_impl=\"pure-rust\"");
    } else if target_os == "macos" {
        if cfg!(feature = "macos-nfs") {
            // Mounts through macOS's own NFS client: nothing to link
            println!("cargo::rustc-cfg=fuser_mount_impl=\"nfs\"");
        } else if cfg!(feature = "macos-no-mount") {
            println!("cargo::rustc-cfg=fuser_mount_impl=\"macos-no-mount\"");
        } else {
            pkg_config::Config::new()
                .atleast_version("2.6.0")
                .probe("fuse") // for macFUSE 4.x
                .map_err(|e| eprintln!("{e}"))
                .unwrap();
            println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse2\"");
            println!("cargo::rustc-cfg=fuser_macfuse_fskit");
        }
    } else if cfg!(feature = "libfuse3") {
        configure_libfuse3().unwrap();
    } else if cfg!(feature = "libfuse2") {
        configure_libfuse2().unwrap();
    } else {
        // First try to link with libfuse3
        match configure_libfuse3() {
            Ok(()) => {}
            Err(e3) => {
                // Fallback to libfuse
                match configure_libfuse2() {
                    Ok(()) => {}
                    Err(e2) => {
                        panic!("Failed to configure libfuse3 or libfuse2: {e3}; {e2}");
                    }
                }
            }
        }
    }
}

fn configure_libfuse3() -> Result<(), pkg_config::Error> {
    pkg_config::Config::new()
        .atleast_version("3.0.0")
        .probe("fuse3")?;
    println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse3\"");
    Ok(())
}

fn configure_libfuse2() -> Result<(), pkg_config::Error> {
    pkg_config::Config::new()
        .atleast_version("2.6.0")
        .probe("fuse")?;
    println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse2\"");
    Ok(())
}
