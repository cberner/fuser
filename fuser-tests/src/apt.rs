//! APT package management helpers

use crate::command_utils::command_success;

pub(crate) async fn apt_install(packages: &[&str]) -> anyhow::Result<()> {
    command_success(
        ["apt", "install", "-y"]
            .into_iter()
            .chain(packages.iter().copied()),
    )
    .await
}

pub(crate) async fn apt_remove(packages: &[&str]) -> anyhow::Result<()> {
    command_success(
        ["apt", "remove", "--purge", "-y"]
            .into_iter()
            .chain(packages.iter().copied()),
    )
    .await?;
    command_success(["apt", "autoremove", "-y"]).await
}
