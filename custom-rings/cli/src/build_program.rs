//! `build`, the SBF program build with pinned platform tools.

use std::{
    path::PathBuf,
    process::{Command, ExitStatus},
    thread,
    time::Duration,
};

use thiserror::Error;

use crate::{
    deploy::default_program_so,
    tool::{ToolError, CARGO_BUILD_SBF},
    BuildArgs, ProjectRoot,
};

/// The platform tools pin the zolana checkout builds with.
pub const DEFAULT_SBF_TOOLS_VERSION: &str = "v1.54";
const INSTALL_ATTEMPTS: u64 = 3;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error(
        "platform tools {version} install exited with {status} after {INSTALL_ATTEMPTS} attempts"
    )]
    InstallFailed { version: String, status: ExitStatus },
    #[error("build finished without {path}")]
    ArtifactMissing { path: PathBuf },
}

pub fn run(
    project_root: &ProjectRoot,
    features: impl Iterator<Item = String>,
    args: BuildArgs,
) -> Result<(), BuildError> {
    let features = feature_list(features);
    let artifact = build(project_root, &args.tools_version, &features)?;
    crate::line("features", &features);
    crate::line("built", artifact.display());
    Ok(())
}

/// A `ring.toml` feature id names a cargo feature of the rendered program.
fn feature_list(features: impl Iterator<Item = String>) -> String {
    let mut list = String::from("bpf-entrypoint");
    for feature in features {
        list.push(',');
        list.push_str(&feature);
    }
    list
}

fn build(
    project_root: &ProjectRoot,
    tools_version: &str,
    features: &str,
) -> Result<PathBuf, BuildError> {
    install_tools(tools_version)?;
    let mut build = command(
        tools_version,
        &[
            "--manifest-path",
            "program/Cargo.toml",
            "--features",
            features,
        ],
    );
    build.current_dir(project_root.as_path());
    CARGO_BUILD_SBF.run(&mut build)?;
    let artifact = default_program_so(project_root);
    if !artifact.exists() {
        return Err(BuildError::ArtifactMissing { path: artifact });
    }
    Ok(artifact)
}

/// The release download flakes, retries back off like CI.
fn install_tools(tools_version: &str) -> Result<(), BuildError> {
    let mut attempt = 1;
    loop {
        let status = CARGO_BUILD_SBF.status(&mut command(tools_version, &["--install-only"]))?;
        if status.success() {
            return Ok(());
        }
        if attempt == INSTALL_ATTEMPTS {
            return Err(BuildError::InstallFailed {
                version: tools_version.to_owned(),
                status,
            });
        }
        println!("platform tools install failed, attempt {attempt}");
        thread::sleep(Duration::from_secs(15 * attempt));
        attempt += 1;
    }
}

fn command(tools_version: &str, args: &[&str]) -> Command {
    let mut command = Command::new("cargo-build-sbf");
    command.args(["--tools-version", tools_version]).args(args);
    command
}
