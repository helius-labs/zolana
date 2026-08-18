//! `solana program deploy` under the authority. The Solana CLI owns the loader
//! v3 write protocol; this only pins the arguments a ring needs.

use std::{path::Path, process::Command};

use anyhow::{anyhow, Context, Result};
use solana_address::Address;
use zolana_client::{Rpc, SolanaRpc};

pub struct Deploy<'a> {
    pub rpc_url: &'a str,
    pub authority_keypair: &'a Path,
    pub program_keypair: &'a Path,
    pub program_so: &'a Path,
}

impl Deploy<'_> {
    /// Deploys (or upgrades) the program with the authority as fee payer and
    /// upgrade authority, then confirms the program account is executable.
    pub fn run(self, rpc: &SolanaRpc, program_id: Address) -> Result<()> {
        for (label, path) in [
            ("authority keypair", self.authority_keypair),
            ("program keypair", self.program_keypair),
            ("program binary", self.program_so),
        ] {
            if !path.exists() {
                return Err(anyhow!("{label} not found at {}", path.display()));
            }
        }
        let status = Command::new("solana")
            .args(["program", "deploy", "--url", self.rpc_url, "--keypair"])
            .arg(self.authority_keypair)
            .arg("--upgrade-authority")
            .arg(self.authority_keypair)
            .arg("--program-id")
            .arg(self.program_keypair)
            .arg(self.program_so)
            .status()
            .context("running `solana program deploy` (is the Solana CLI installed?)")?;
        if !status.success() {
            return Err(anyhow!("solana program deploy exited with {status}"));
        }
        let account = rpc
            .get_account(program_id)?
            .ok_or_else(|| anyhow!("program account {program_id} missing after deploy"))?;
        if !account.executable {
            return Err(anyhow!("program account {program_id} is not executable"));
        }
        Ok(())
    }
}
