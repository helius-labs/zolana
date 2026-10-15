//! One place a subprocess is spawned and its exit judged.

use std::{
    io,
    process::{Command, Stdio},
};

use anyhow::{anyhow, ensure, Result};

pub const ANZA_INSTALL: &str = r#"install the Anza toolchain with sh -c "$(curl -sSfL https://release.anza.xyz/v4.2.2/install)""#;

pub const SOLANA: Tool = Tool::new("solana", ANZA_INSTALL);
pub const SOLANA_TEST_VALIDATOR: Tool = Tool::new("solana-test-validator", ANZA_INSTALL);
pub const ZOLANA: Tool = Tool::new(
    "zolana",
    "install the zolana cli from the latest zolana release",
);

#[derive(Debug, Clone, Copy)]
pub struct Tool {
    pub name: &'static str,
    pub install: &'static str,
}

impl Tool {
    pub const fn new(name: &'static str, install: &'static str) -> Self {
        Self { name, install }
    }

    /// The subcommand the error names, `SOLANA.named("solana program deploy")`.
    pub fn named(self, name: &'static str) -> Self {
        Self { name, ..self }
    }

    pub fn run(self, command: &mut Command) -> Result<()> {
        let status = command.status().map_err(|error| self.spawn_error(error))?;
        ensure!(status.success(), "{} exited with {status}", self.name);
        Ok(())
    }

    /// `--version` is the one flag every tool here answers.
    pub fn check_installed(self) -> Result<()> {
        Command::new(self.name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| self.spawn_error(error))?;
        Ok(())
    }

    fn spawn_error(self, error: io::Error) -> anyhow::Error {
        match error.kind() {
            io::ErrorKind::NotFound => anyhow!("{} is not installed, {}", self.name, self.install),
            _ => anyhow::Error::new(error).context(format!("cannot run {}", self.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_tool_names_its_install_and_a_failure_its_status() {
        let missing = Tool::new("zolana-ring-no-such-tool", "install it");
        let error = missing.check_installed().expect_err("missing");
        assert_eq!(
            error.to_string(),
            "zolana-ring-no-such-tool is not installed, install it"
        );
        let failing = Tool::new("false", "");
        let error = failing.run(&mut Command::new("false")).expect_err("fails");
        assert!(
            error.to_string().starts_with("false exited with"),
            "{error}"
        );
    }
}
