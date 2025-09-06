// A small client to exercise the ioctl example filesystem.
//
// Usage:
//   1) In one shell, mount the example:
//        cargo run --example ioctl DIR
//   2) In another shell, run this client to test setting/getting size:
//        cargo run --example ioctl_client DIR
//
// Ioctl actions:
//   - GET size
//   - SET size to 4096
//   - GET size (expect 4096)
//   - SET size to 0
//   - GET size (expect 0)

#![allow(clippy::cast_possible_truncation)]

use clap::{Arg, Command, crate_version};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

// Generate wrappers matching examples/ioctl.rs
nix::ioctl_read!(ioctl_get_size, 'E', 0, usize);
nix::ioctl_write_ptr!(ioctl_set_size, 'E', 1, usize);

// Helper to GET size
fn get_size(fd: i32) -> nix::Result<usize> {
    let mut out: usize = 0;
    unsafe {
        ioctl_get_size(fd, &raw mut out)?;
    }
    Ok(out)
}

// Helper to SET size
fn set_size(fd: i32, sz: usize) -> nix::Result<()> {
    let mut val = sz;
    unsafe {
        ioctl_set_size(fd, &raw mut val)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let matches = Command::new("ioctl_client")
        .version(crate_version!())
        .author("Richard Lawrence")
        .arg(
            Arg::new("IOCTL_MOUNT_POINT")
                .required(true)
                .index(1)
                .help("Test an example Ioctl filesystem mounted at the given path"),
        )
        .get_matches();
    env_logger::init();
    let mountpoint = matches.get_one::<String>("MOUNT_POINT").unwrap();
    let dir = PathBuf::from(mountpoint);
    assert!(
        dir.is_dir(),
        "MOUNT_POINT does not look like a valid directory"
    );
    // Open the example file in the current directory mount
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("fioc"))
        .expect("File `fioc` not opened. (Are you sure Ioctl is mounted correctly?)");
    let fd = f.as_raw_fd();

    // 1) Read current size
    match get_size(fd) {
        Ok(sz) => println!("Initial size: {sz} bytes"),
        Err(e) => {
            eprintln!("FIOC_GET_SIZE failed: {e}");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ioctl get failed: {e}"),
            ));
        }
    }

    // 2) Set size to 4096
    if let Err(e) = set_size(fd, 4096) {
        eprintln!("FIOC_SET_SIZE(4096) failed: {e}");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("ioctl set failed: {e}"),
        ));
    }
    println!("Set size to 4096 bytes");

    // 3) Get size and expect 4096
    match get_size(fd) {
        Ok(sz) => {
            println!("After set(4096), size: {sz} bytes");
            if sz != 4096 {
                eprintln!("Unexpected size after set(4096): got {sz}, expected 4096");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("size mismatch after set(4096): {sz}"),
                ));
            }
        }
        Err(e) => {
            eprintln!("FIOC_GET_SIZE failed after set(4096): {e}");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ioctl get failed: {e}"),
            ));
        }
    }

    // 4) Set size to 0
    if let Err(e) = set_size(fd, 0) {
        eprintln!("FIOC_SET_SIZE(0) failed: {e}");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("ioctl set failed: {e}"),
        ));
    }
    println!("Set size to 0 bytes");

    // 5) Get size and expect 0
    match get_size(fd) {
        Ok(sz) => {
            println!("After set(0), size: {sz} bytes");
            if sz != 0 {
                eprintln!("Unexpected size after set(0): got {sz}, expected 0");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("size mismatch after set(0): {sz}"),
                ));
            }
        }
        Err(e) => {
            eprintln!("FIOC_GET_SIZE failed after set(0): {e}");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ioctl get failed: {e}"),
            ));
        }
    }

    // Write a newline to stdout to flush buffered output (looks better in some environments)
    io::stdout().flush().ok();

    println!("ioctl_client completed successfully.");
    Ok(())
}
