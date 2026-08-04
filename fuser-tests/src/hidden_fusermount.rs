//! Hiding the FUSE mount helpers, to test what fuser does without them

use std::path::PathBuf;

use anyhow::Context;
use tokio::fs;

/// Renames every mount helper out of the way for as long as it is held, so that fuser
/// finds none. The helpers `detect_fusermount_bin()` looks for are either bare names it
/// resolves through PATH or paths under /sbin and /bin, and both of those are symlinks
/// into /usr on the distributions the tests run on, so renaming the files below covers
/// every candidate.
pub(crate) struct HiddenFusermount {
    /// Where each helper was moved from, and to
    hidden: Vec<(PathBuf, PathBuf)>,
}

impl HiddenFusermount {
    const HELPERS: [&'static str; 4] = [
        "/usr/bin/fusermount3",
        "/usr/bin/fusermount",
        "/usr/sbin/fusermount3",
        "/usr/sbin/fusermount",
    ];

    pub(crate) async fn hide() -> anyhow::Result<Self> {
        let mut hidden = Vec::new();
        for helper in Self::HELPERS {
            let from = PathBuf::from(helper);
            // Not following symlinks: one helper is usually a symlink to the other, and
            // leaving it behind pointing at a renamed target would be enough to fail the
            // test for the wrong reason
            if fs::symlink_metadata(&from).await.is_err() {
                continue;
            }
            let to = from.with_extension("hidden");
            fs::rename(&from, &to)
                .await
                .context(format!("Failed to rename {}", from.display()))?;
            hidden.push((from, to));
        }
        anyhow::ensure!(
            !hidden.is_empty(),
            "No FUSE mount helper found to hide, so the test would prove nothing"
        );
        Ok(Self { hidden })
    }
}

impl Drop for HiddenFusermount {
    fn drop(&mut self) {
        // Every later test needs the helpers back, so report a failure to restore them
        // rather than letting it show up as an unrelated test failing
        for (from, to) in &self.hidden {
            if let Err(err) = std::fs::rename(to, from) {
                eprintln!("Failed to restore {}: {err}", from.display());
            }
        }
    }
}
