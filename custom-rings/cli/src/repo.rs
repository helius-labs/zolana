//! `repo`, the GitHub repository for a generated ring.

use std::{path::Path, process::Command};

use crate::{
    config::RingConfig,
    tool::{ToolError, GH, GIT},
};

pub fn run(config: &RingConfig) -> Result<(), ToolError> {
    if !Path::new(".git").exists() {
        GIT.named("git init")
            .run(Command::new("git").args(["init", "-q", "-b", "main"]))?;
    }
    GH.named("gh repo create").run(Command::new("gh").args([
        "repo",
        "create",
        &config.name,
        "--private",
        "--source",
        ".",
        "--push",
    ]))
}
