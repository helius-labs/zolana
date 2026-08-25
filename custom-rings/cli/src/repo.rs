//! `repo`, the GitHub repository for a generated ring.

use std::process::Command;

use crate::{
    tool::{ToolError, GH, GIT},
    Context,
};

pub fn run(ctx: &Context) -> Result<(), ToolError> {
    if !ctx
        .project_root
        .resolve(std::path::Path::new(".git"))
        .exists()
    {
        GIT.named("git init").run(
            Command::new("git")
                .current_dir(ctx.project_root.as_path())
                .args(["init", "-q", "-b", "main"]),
        )?;
    }
    GH.named("gh repo create").run(
        Command::new("gh")
            .current_dir(ctx.project_root.as_path())
            .args([
                "repo",
                "create",
                &ctx.config.name,
                "--private",
                "--source",
                ".",
                "--push",
            ]),
    )
}
