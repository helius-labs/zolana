//! Upgrade authority changes through `solana program set-upgrade-authority`.

use std::{path::Path, process::Command};

use anyhow::{anyhow, Context, Result};
use solana_address::Address;

use crate::deploy::{read_program_data, ProgramDataInfo};

pub struct SetUpgradeAuthority<'a> {
    pub rpc_url: &'a str,
    pub authority_keypair: &'a Path,
    pub authority: Address,
    pub program_id: Address,
}

impl SetUpgradeAuthority<'_> {
    /// Hands the program to `new_authority`. Only that key can `deploy` and,
    /// while the config is not created, `create_config` afterwards, so
    /// ring.toml has to follow.
    pub fn transfer(self, current: &ProgramDataInfo, new_authority: Address) -> Result<()> {
        self.check_current(current)?;
        self.run(&[
            "--new-upgrade-authority",
            &new_authority.to_string(),
            "--skip-new-upgrade-authority-signer-check",
        ])
    }

    /// Makes the program immutable. Irreversible, and `create_config` falls back
    /// to plain authority gating for a config that does not exist yet.
    pub fn renounce(self, current: &ProgramDataInfo) -> Result<()> {
        self.check_current(current)?;
        self.run(&["--final"])
    }

    fn check_current(&self, current: &ProgramDataInfo) -> Result<()> {
        match current.upgrade_authority {
            Some(authority) if authority == self.authority => Ok(()),
            Some(authority) => Err(anyhow!(
                "program {} is upgradeable by {authority}, ring.toml names {}",
                self.program_id,
                self.authority
            )),
            None => Err(anyhow!("program {} is already immutable", self.program_id)),
        }
    }

    fn run(&self, args: &[&str]) -> Result<()> {
        let status = Command::new("solana")
            .args([
                "program",
                "set-upgrade-authority",
                "--url",
                self.rpc_url,
                "--keypair",
            ])
            .arg(self.authority_keypair)
            .arg(self.program_id.to_string())
            .args(args)
            .status()
            .context("running `solana program set-upgrade-authority`")?;
        if !status.success() {
            return Err(anyhow!(
                "solana program set-upgrade-authority exited with {status}"
            ));
        }
        Ok(())
    }
}

pub fn deployed_program_data<R: zolana_client::Rpc>(
    rpc: &R,
    program_id: Address,
) -> Result<ProgramDataInfo> {
    read_program_data(rpc, program_id)?
        .ok_or_else(|| anyhow!("program {program_id} is not deployed under the upgradeable loader"))
}
