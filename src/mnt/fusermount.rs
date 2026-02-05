use crate::UnmountOption;
use crate::ll::errno;
use crate::mnt::unmount_options;
use log::{debug, error};
use regex::bytes::Regex;
use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use std::process::Stdio;
use std::{io, path::Path};

pub(crate) const FUSERMOUNT_BIN: &str = "fusermount";
pub(crate) const FUSERMOUNT3_BIN: &str = "fusermount3";
pub(crate) const MOUNT_FUSEFS_BIN: &str = "mount_fusefs";

pub(crate) fn detect_fusermount_bin() -> String {
    if let Some(fusermount) = env::var_os("FUSERMOUNT_PATH") {
        return fusermount
            .to_str()
            .expect("FUSERMOUNT_PATH is not UTF-8")
            .to_owned();
    }

    for name in [
        FUSERMOUNT3_BIN.to_string(),
        FUSERMOUNT_BIN.to_string(),
        MOUNT_FUSEFS_BIN.to_string(),
        format!("/sbin/{FUSERMOUNT3_BIN}"),
        format!("/sbin/{FUSERMOUNT_BIN}"),
        format!("/sbin/{MOUNT_FUSEFS_BIN}"),
        format!("/bin/{FUSERMOUNT3_BIN}"),
        format!("/bin/{FUSERMOUNT_BIN}"),
    ]
    .iter()
    {
        if Command::new(name).arg("-h").output().is_ok() {
            return name.to_string();
        }
    }
    // Default to fusermount3
    FUSERMOUNT3_BIN.to_string()
}

pub(crate) fn fuse_unmount_pure(
    mountpoint: &Path,
    flags: &[UnmountOption],
) -> Result<(), io::Error> {
    let nix_flags =
        nix::mount::MntFlags::from_bits_retain(unmount_options::to_unmount_syscall(flags));
    #[cfg(target_os = "linux")]
    match nix::mount::umount2(mountpoint, nix_flags) {
        Ok(()) => return Ok(()),
        Err(nix::errno::Errno::EPERM) => {}
        Err(e) => return Err(e.into()),
    }
    #[cfg(target_os = "macos")]
    match nix::mount::unmount(mountpoint, nix_flags) {
        Ok(()) => return Ok(()),
        Err(e) if e == nix::errno::Errno::EPERM => {}
        Err(e) => return Err(e.into()),
    }
    let mut builder = Command::new(detect_fusermount_bin());
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    builder.arg("-u");
    for flag in flags {
        if let Some(cmd_arg) = unmount_options::to_fusermount_option(flag) {
            builder.arg(cmd_arg);
        }
    }
    builder
        .arg("--")
        .arg(OsStr::new(&mountpoint.to_string_lossy().into_owned()));
    match builder.output() {
        Ok(output) => {
            debug!(
                "fusermount stdout on {}: {}",
                mountpoint.display(),
                String::from_utf8_lossy(&output.stdout)
            );
            debug!(
                "fusermount stderr on {}: {}",
                mountpoint.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            if output.status.success() {
                Ok(())
            } else {
                let fusermount_error =
                    match parse_fusermount_unmount_stderr(OsStr::from_bytes(&output.stderr)) {
                        Some(e) => e,
                        None => {
                            error!(
                                "failed to parse fusermount umount error message: {:?}",
                                output.stderr
                            );
                            return Err(io::Error::new(
                                ErrorKind::Other,
                                "Failed to parse fusermount umount error message",
                            ));
                        }
                    };
                // Since `fusermount` does not invoke any locale functions,
                // the locale used for `strerror` in the program is guaranteed to be `C`.
                let errno = errno::get_errno_by_message(
                    &fusermount_error,
                    &"C".try_into().expect("locale should be valid"),
                )
                .map_err(|e| {
                    error!("failed to get errno by fusermount umount message: {}", e);
                    io::Error::new(
                        ErrorKind::Other,
                        "failed to get errno by fusermount umount message",
                    )
                })?
                .ok_or_else(|| {
                    error!(
                        "errno not found for fusermount umount message: {:?}",
                        fusermount_error
                    );
                    io::Error::new(
                        ErrorKind::Other,
                        "errno not found for fusermount umount message",
                    )
                })?;
                Err(io::Error::from_raw_os_error(errno.code()))
            }
        }
        Err(e) => Err(e),
    }
}

fn parse_fusermount_unmount_stderr(output: &OsStr) -> Option<OsString> {
    let parse_regex = Regex::new(r"([^:]+): failed to unmount ([^:]+): (.+)")
        .expect("built-in regex should be valid");
    parse_regex.captures(output.as_bytes()).map(|captures| {
        let error = captures.get(3).map(|m| m.as_bytes()).unwrap_or_default();
        OsStr::from_bytes(error).to_os_string()
    })
}
