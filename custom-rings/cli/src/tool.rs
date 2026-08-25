//! One place a subprocess is spawned and its exit judged.

use std::{
    io,
    process::{Command, ExitStatus},
};

use thiserror::Error;

pub const ANZA_INSTALL: &str = r#"install the Anza toolchain with sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)""#;

pub const SOLANA: Tool = Tool {
    name: "solana",
    install: ANZA_INSTALL,
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
    /// The subcommand the error names, `SOLANA.named("solana program deploy")`.
    pub fn named(self, name: &'static str) -> Self {
        Self { name, ..self }
    }

    pub fn run(self, command: &mut Command) -> Result<(), ToolError> {
        let status = command.status().map_err(|source| self.spawn(source))?;
        self.check(status)
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
