//! `solana program deploy` under the authority. The Solana CLI owns the loader
//! v3 write protocol; this pins the arguments a ring needs and prepares an
//! upgrade the CLI would otherwise refuse.

use std::{path::Path, process::Command};

use anyhow::{anyhow, Context, Result};
use custom_ring_sdk::program_data_pda;
use solana_address::Address;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_client::{Rpc, SolanaRpc};

pub struct Deploy<'a> {
    pub rpc_url: &'a str,
    pub authority_keypair: &'a Path,
    pub authority: Address,
    /// Needed for the first deploy only. An upgrade names the program by id.
    pub program_keypair: &'a Path,
    pub program_so: &'a Path,
}

/// The loader refuses to grow `ProgramData` by less than this.
const MIN_EXTEND_BYTES: usize = 10_240;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployOutcome {
    Deployed,
    Upgraded,
}

/// The loader-v3 `ProgramData` of a deployed program, who may upgrade it and
/// how many bytecode bytes it can hold.
pub struct ProgramDataInfo {
    pub upgrade_authority: Option<Address>,
    pub capacity: usize,
}

impl Deploy<'_> {
    pub fn run(self, rpc: &SolanaRpc, program_id: Address) -> Result<DeployOutcome> {
        for (label, path) in [
            ("authority keypair", self.authority_keypair),
            ("program binary", self.program_so),
        ] {
            if !path.exists() {
                return Err(anyhow!("{label} not found at {}", path.display()));
            }
        }
        let so_len = std::fs::metadata(self.program_so)
            .with_context(|| format!("reading {}", self.program_so.display()))?
            .len() as usize;

        let deployed = read_program_data(rpc, program_id)?;
        if let Some(info) = &deployed {
            match info.upgrade_authority {
                Some(authority) if authority == self.authority => {}
                Some(authority) => {
                    return Err(anyhow!(
                        "program {program_id} is upgradeable by {authority}, ring.toml names {}",
                        self.authority
                    ))
                }
                None => {
                    return Err(anyhow!(
                        "program {program_id} is immutable, it cannot be upgraded"
                    ))
                }
            }
            if so_len > info.capacity {
                self.extend(program_id, (so_len - info.capacity).max(MIN_EXTEND_BYTES))?;
            }
        } else if !self.program_keypair.exists() {
            return Err(anyhow!(
                "program keypair not found at {}, the first deploy needs it",
                self.program_keypair.display()
            ));
        }

        let mut command = Command::new("solana");
        command
            .args(["program", "deploy", "--url", self.rpc_url, "--keypair"])
            .arg(self.authority_keypair)
            .arg("--upgrade-authority")
            .arg(self.authority_keypair)
            .arg("--program-id");
        if deployed.is_some() {
            command.arg(program_id.to_string());
        } else {
            command.arg(self.program_keypair);
        }
        let status = command
            .arg(self.program_so)
            .status()
            .context("running `solana program deploy` (is the Solana CLI installed?)")?;
        if !status.success() {
            return Err(anyhow!("solana program deploy exited with {status}"));
        }
        rpc.assert_executable(&program_id)
            .with_context(|| format!("program {program_id} after deploy"))?;
        Ok(if deployed.is_some() {
            DeployOutcome::Upgraded
        } else {
            DeployOutcome::Deployed
        })
    }

    /// Grows `ProgramData` so a larger binary fits. The loader refuses an
    /// upgrade that does not.
    fn extend(&self, program_id: Address, additional_bytes: usize) -> Result<()> {
        println!("extending program data by {additional_bytes} bytes");
        let status = Command::new("solana")
            .args(["program", "extend", "--url", self.rpc_url, "--keypair"])
            .arg(self.authority_keypair)
            .arg(program_id.to_string())
            .arg(additional_bytes.to_string())
            .status()
            .context("running `solana program extend`")?;
        if !status.success() {
            return Err(anyhow!("solana program extend exited with {status}"));
        }
        Ok(())
    }
}

/// `None` when the program is not deployed under the upgradeable loader.
pub fn read_program_data<R: Rpc>(rpc: &R, program_id: Address) -> Result<Option<ProgramDataInfo>> {
    if rpc.get_account(program_id)?.is_none() {
        return Ok(None);
    }
    let Some(account) = rpc.get_account(program_data_pda())? else {
        return Ok(None);
    };
    let (state, _) = bincode::serde::decode_from_slice::<UpgradeableLoaderState, _>(
        &account.data,
        bincode::config::legacy(),
    )
    .map_err(|_| anyhow!("program data account of {program_id} has an unexpected layout"))?;
    let UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    } = state
    else {
        return Err(anyhow!(
            "{} is not a ProgramData account",
            program_data_pda()
        ));
    };
    Ok(Some(ProgramDataInfo {
        upgrade_authority: upgrade_authority_address
            .map(|key| Address::new_from_array(key.to_bytes()))
            .filter(|key| *key != Address::default()),
        capacity: account
            .data
            .len()
            .saturating_sub(UpgradeableLoaderState::size_of_programdata_metadata()),
    }))
}
