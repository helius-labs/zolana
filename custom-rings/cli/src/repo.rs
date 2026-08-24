//! `repo`, the GitHub repository for a generated ring.

use std::{
    io,
    path::Path,
    process::{Command, ExitStatus},
};

use thiserror::Error;

use crate::config::RingConfig;

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("gh is not installed, install the GitHub CLI from https://cli.github.com and run `gh auth login`")]
    GhMissing(#[source] io::Error),
    #[error("cannot run {tool}")]
    Spawn {
        tool: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{tool} exited with {status}")]
    Failed {
        tool: &'static str,
        status: ExitStatus,
    },
}

pub fn run(config: &RingConfig) -> Result<(), RepoError> {
    if !Path::new(".git").exists() {
        let status = Command::new("git")
            .args(["init", "-q", "-b", "main"])
            .status()
            .map_err(|source| RepoError::Spawn {
                tool: "git",
                source,
            })?;
        if !status.success() {
            return Err(RepoError::Failed {
                tool: "git init",
                status,
            });
        }
    }
    let status = Command::new("gh")
        .args([
            "repo",
            "create",
            &config.name,
            "--private",
            "--source",
            ".",
            "--push",
        ])
        .status()
        .map_err(|source| match source.kind() {
            io::ErrorKind::NotFound => RepoError::GhMissing(source),
            _ => RepoError::Spawn { tool: "gh", source },
        })?;
    if !status.success() {
        return Err(RepoError::Failed {
            tool: "gh repo create",
            status,
        });
    }
    Ok(())
}
