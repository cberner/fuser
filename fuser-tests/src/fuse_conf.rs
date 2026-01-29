//! Functions for managing /etc/fuse.conf

use crate::command_utils::command_success;

pub(crate) async fn fuse_conf_write_user_allow_other() -> anyhow::Result<()> {
    command_success(["sh", "-c", "echo 'user_allow_other' >> /etc/fuse.conf"]).await
}

pub(crate) async fn fuse_conf_remove_user_allow_other() -> anyhow::Result<()> {
    command_success(["sed", "-i", "/user_allow_other/d", "/etc/fuse.conf"]).await
}
