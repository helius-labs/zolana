use std::{fmt::Write, fs, path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use feature_gate::find_features;
use solana_account::Account;
use solana_address::Address;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_loader_v4_interface::state::LoaderV4State;
use solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4};
use spr_interface::PROGRAM_ID_PUBKEY;

use crate::{init_protocol::Cluster, rpc::SolanaRpc};

struct Options {
    so: Option<PathBuf>,
    program_id: Address,
    rpc_url: String,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut so = None;
        let mut program_id = None;
        let mut rpc_url = None;
        let mut cluster = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| anyhow!("{arg} requires a value"))?;
            match arg.as_str() {
                "--so" => so = Some(PathBuf::from(value)),
                "--program-id" => {
                    program_id = Some(Address::from_str(&value).context("invalid --program-id")?)
                }
                "--rpc-url" => rpc_url = Some(value),
                "--cluster" => cluster = Some(Cluster::parse(&value)?),
                _ => bail!("unexpected argument {arg:?}"),
            }
        }
        if so.is_some() && (program_id.is_some() || rpc_url.is_some() || cluster.is_some()) {
            bail!("--so cannot be combined with a deployed program source");
        }
        Ok(Self {
            so,
            program_id: program_id.unwrap_or(PROGRAM_ID_PUBKEY),
            rpc_url: rpc_url.unwrap_or_else(|| {
                cluster
                    .unwrap_or(Cluster::Localnet)
                    .default_url()
                    .to_string()
            }),
        })
    }
}

pub fn run(args: Vec<String>) -> Result<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!("Usage: zolana-protocol circuit-features [--so <program.so> | --program-id <address> [--cluster localnet|devnet|mainnet] [--rpc-url <url>]]\n\nDefaults to the shielded-pool program on localnet. Reads compile-time feature states and proving-key SHA256 hashes from the program binary.");
        return Ok(());
    }
    let options = Options::parse(args)?;
    let binary = match options.so {
        Some(path) => fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        None => deployed_binary(&SolanaRpc::new(options.rpc_url), options.program_id)?,
    };
    print!("{}", report(&binary)?);
    Ok(())
}

fn report(binary: &[u8]) -> Result<String> {
    let features = find_features(binary)?;
    if features.is_empty() {
        bail!("program has no feature-gate metadata; its active features are unknown");
    }
    let mut report = String::new();
    for feature in features {
        writeln!(
            report,
            "{}: {}",
            feature.name,
            if feature.enabled {
                "enabled"
            } else {
                "disabled"
            }
        )?;
        for hash in feature.proving_key_sha256s {
            write!(report, "  proving_key_sha256=")?;
            for byte in hash {
                write!(report, "{byte:02x}")?;
            }
            report.push('\n');
        }
    }
    Ok(report)
}

fn deployed_binary(rpc: &SolanaRpc, program_id: Address) -> Result<Vec<u8>> {
    let program = rpc
        .get_account(program_id)?
        .ok_or_else(|| anyhow!("program {program_id} not found"))?;
    if !program.executable {
        bail!("{program_id} is not executable");
    }
    if program.owner == bpf_loader_upgradeable::ID {
        let UpgradeableLoaderState::Program {
            programdata_address,
        } = bincode::deserialize(&program.data).context("decode program loader state")?
        else {
            bail!("{program_id} is not an upgradeable program account");
        };
        let data = rpc
            .get_account(programdata_address)?
            .ok_or_else(|| anyhow!("ProgramData {programdata_address} not found"))?;
        upgradeable_binary(&data)
    } else if program.owner == loader_v4::ID {
        if program.data.len() < LoaderV4State::program_data_offset() {
            bail!("truncated loader-v4 program");
        }
        Ok(program
            .data
            .get(LoaderV4State::program_data_offset()..)
            .context("missing loader-v4 program bytes")?
            .to_vec())
    } else if program.owner == bpf_loader::ID || program.owner == bpf_loader_deprecated::ID {
        Ok(program.data)
    } else {
        bail!("{program_id} is not owned by a supported program loader");
    }
}

fn upgradeable_binary(account: &Account) -> Result<Vec<u8>> {
    if account.owner != bpf_loader_upgradeable::ID {
        bail!("ProgramData is not owned by the upgradeable loader");
    }
    let state: UpgradeableLoaderState =
        bincode::deserialize(&account.data).context("decode ProgramData loader state")?;
    if !matches!(state, UpgradeableLoaderState::ProgramData { .. }) {
        bail!("expected a ProgramData account");
    }
    Ok(account
        .data
        .get(UpgradeableLoaderState::size_of_programdata_metadata()..)
        .context("missing ProgramData binary")?
        .to_vec())
}

#[cfg(test)]
#[path = "circuit_features_test.rs"]
mod tests;
