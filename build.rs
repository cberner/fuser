fn main() {
    // Register rustc cfg for switching between mount implementations.
    println!(
        "cargo::rustc-check-cfg=cfg(fuser_mount_impl, values(\"pure-rust\", \"libfuse2\", \"libfuse3\"))"
    );

    let target_os =
        std::env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS should be set");

    if matches!(
        target_os.as_str(),
        "linux" | "freebsd" | "dragonfly" | "openbsd" | "netbsd"
    ) && cfg!(not(feature = "libfuse"))
    {
        println!("cargo::rustc-cfg=fuser_mount_impl=\"pure-rust\"");
    } else if target_os == "macos" {
        pkg_config::Config::new()
            .atleast_version("2.6.0")
            .probe("fuse") // for macFUSE
            .map_err(|e| eprintln!("{e}"))
            .unwrap();
        println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse2\"");
        // Note: We use runtime detection for macFUSE 4.x vs 5.x protocol differences
        // in request.rs instead of the compile-time macfuse-4-compat feature.
        // This allows the binary to work with both macFUSE 4.x and 5.x installations.
    } else {
        // First try to link with libfuse3
        if pkg_config::Config::new()
            .atleast_version("3.0.0")
            .probe("fuse3")
            .map_err(|e| eprintln!("{e}"))
            .is_ok()
        {
            println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse3\"");
        } else {
            // Fallback to libfuse
            pkg_config::Config::new()
                .atleast_version("2.6.0")
                .probe("fuse")
                .map_err(|e| eprintln!("{e}"))
                .unwrap();
            println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse2\"");
        }
    }
}
