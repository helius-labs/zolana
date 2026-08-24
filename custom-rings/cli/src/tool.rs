//! One place a subprocess is spawned and its exit judged.

use std::{
    io,
    process::{Command, ExitStatus},
};

use thiserror::Error;

pub const ANZA_INSTALL: &str = r#"install the Anza toolchain with sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)""#;

pub const GIT: Tool = Tool {
    name: "git",
    install: "install git",
};
pub const CARGO_GENERATE: Tool = Tool {
    name: "cargo generate",
    install: "run `cargo install cargo-generate --locked`",
};
pub const SOLANA: Tool = Tool {
    name: "solana",
    install: ANZA_INSTALL,
};
pub const CARGO_BUILD_SBF: Tool = Tool {
    name: "cargo-build-sbf",
    install: ANZA_INSTALL,
};
pub const GH: Tool = Tool {
    name: "gh",
    install: "install the GitHub CLI from https://cli.github.com and run `gh auth login`",
};

#[derive(Debug, Clone, Copy)]
pub struct Tool {
    pub name: &'static str,
    pub install: &'static str,
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("{name} is not installed, {install}")]
    Missing {
        name: &'static str,
        install: &'static str,
    },
    #[error("cannot run {name}")]
    Spawn {
        name: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{name} exited with {status}")]
    Failed {
        name: &'static str,
        status: ExitStatus,
    },
}

impl Tool {
    /// The subcommand the error names, `GIT.named("git init")`.
    pub fn named(self, name: &'static str) -> Self {
        Self { name, ..self }
    }

    /// A failing version probe reads as not installed.
    pub fn require(self, probe: &mut Command) -> Result<(), ToolError> {
        match probe.output() {
            Ok(output) if output.status.success() => Ok(()),
            _ => Err(ToolError::Missing {
                name: self.name,
                install: self.install,
            }),
        }
    }

    pub fn run(self, command: &mut Command) -> Result<(), ToolError> {
        let status = self.status(command)?;
        self.check(status)
    }

    /// Trimmed stdout of a successful run.
    pub fn capture(self, command: &mut Command) -> Result<String, ToolError> {
        let output = command.output().map_err(|source| self.spawn(source))?;
        self.check(output.status)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Output shown only on failure, the caller narrates the action.
    pub fn run_captured(self, command: &mut Command) -> Result<(), ToolError> {
        let output = command.output().map_err(|source| self.spawn(source))?;
        if !output.status.success() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        self.check(output.status)
    }

    /// The exit status alone, a retry loop judges it itself.
    pub fn status(self, command: &mut Command) -> Result<ExitStatus, ToolError> {
        command.status().map_err(|source| self.spawn(source))
    }

    pub fn check(self, status: ExitStatus) -> Result<(), ToolError> {
        if status.success() {
            Ok(())
        } else {
            Err(ToolError::Failed {
                name: self.name,
                status,
            })
        }
    }

    fn spawn(self, source: io::Error) -> ToolError {
        match source.kind() {
            io::ErrorKind::NotFound => ToolError::Missing {
                name: self.name,
                install: self.install,
            },
            _ => ToolError::Spawn {
                name: self.name,
                source,
            },
        }
    }
}
