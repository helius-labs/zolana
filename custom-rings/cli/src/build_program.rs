//! `build`, the SBF program build with pinned platform tools.

use std::{
    io,
    path::PathBuf,
    process::{Command, ExitStatus},
    thread,
    time::Duration,
};

use thiserror::Error;

use crate::{config::RingConfig, deploy::default_program_so, BuildArgs};

/// The platform tools pin the zolana checkout builds with.
pub const DEFAULT_SBF_TOOLS_VERSION: &str = "v1.54";
const INSTALL_ATTEMPTS: u64 = 3;
const ANZA_INSTALL: &str = r#"sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)""#;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cargo-build-sbf is not installed, install the Anza toolchain with {ANZA_INSTALL}")]
    CargoBuildSbfMissing(#[source] io::Error),
    #[error("cannot run cargo-build-sbf")]
    Spawn(#[source] io::Error),
    #[error(
        "platform tools {version} install exited with {status} after {INSTALL_ATTEMPTS} attempts"
    )]
    InstallFailed { version: String, status: ExitStatus },
    #[error("cargo-build-sbf exited with {status}")]
    BuildFailed { status: ExitStatus },
    #[error("build finished without {path}")]
    ArtifactMissing { path: PathBuf },
}

pub struct BuildProgram<'a> {
    pub tools_version: &'a str,
}

pub fn run(_config: &RingConfig, args: BuildArgs) -> Result<(), BuildError> {
    let artifact = BuildProgram {
        tools_version: &args.tools_version,
    }
    .build()?;
    println!("built       {}", artifact.display());
    Ok(())
}

impl BuildProgram<'_> {
    pub fn build(self) -> Result<PathBuf, BuildError> {
        self.install_tools()?;
        let status = self
            .command(&[
                "--manifest-path",
                "program/Cargo.toml",
                "--features",
                "bpf-entrypoint",
            ])
            .status()
            .map_err(spawn_error)?;
        if !status.success() {
            return Err(BuildError::BuildFailed { status });
        }
        let artifact = default_program_so();
        if !artifact.exists() {
            return Err(BuildError::ArtifactMissing { path: artifact });
        }
        Ok(artifact)
    }

    /// The release download flakes, retries back off like CI.
    fn install_tools(&self) -> Result<(), BuildError> {
        let mut attempt = 1;
        loop {
            let status = self
                .command(&["--install-only"])
                .status()
                .map_err(spawn_error)?;
            if status.success() {
                return Ok(());
            }
            if attempt == INSTALL_ATTEMPTS {
                return Err(BuildError::InstallFailed {
                    version: self.tools_version.to_owned(),
                    status,
                });
            }
            println!("platform tools install failed, attempt {attempt}");
            thread::sleep(Duration::from_secs(15 * attempt));
            attempt += 1;
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("cargo-build-sbf");
        command
            .args(["--tools-version", self.tools_version])
            .args(args);
        command
    }
}

fn spawn_error(source: io::Error) -> BuildError {
    if source.kind() == io::ErrorKind::NotFound {
        BuildError::CargoBuildSbfMissing(source)
    } else {
        BuildError::Spawn(source)
    }
}
