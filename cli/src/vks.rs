//! `zolana vks`: read the setup marker groth16-solana embeds next to every
//! verifying key, from a deployed program or a local `.so`, and check the
//! markers against this build's verifying keys. A deployment that passes
//! carries no insecure test setup and verifies exactly the proving keys this
//! build's prover and clients pin.

use std::{collections::BTreeMap, fs, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use groth16_solana::vk::setup::{find_setup_txts, SetupTxt};
use solana_address::Address;
use solana_loader_v3_interface::{get_program_data_address, state::UpgradeableLoaderState};
use zolana_client::{prover::known_proving_keys, ProverClient, Rpc, SolanaRpc};
use zolana_interface::{BPF_LOADER_UPGRADEABLE_PUBKEY, PROGRAM_ID_PUBKEY};

use crate::{
    args::{VksCheckOptions, VksCommand, VksSourceOptions},
    cli_config::{resolve_rpc_url, CliConfigFile},
};

/// Loader-v3 `UpgradeableLoaderState::ProgramData` discriminant, little endian.
const PROGRAM_DATA_TAG: [u8; 4] = [3, 0, 0, 0];

pub(crate) fn run_vks(command: VksCommand) -> Result<()> {
    match command {
        VksCommand::List(source) => {
            let markers = read_markers(&source)?;
            let known = known_keys();
            for marker in &markers {
                println!("{}", list_line(marker, &known));
            }
            println!("{} verifying key(s)", markers.len());
            Ok(())
        }
        VksCommand::Check(opts) => run_check(opts),
    }
}

fn run_check(opts: VksCheckOptions) -> Result<()> {
    let markers = read_markers(&opts.source)?;
    let known = known_keys();
    let problems = check_markers(&markers, &known);
    if !problems.is_empty() {
        bail!(
            "program verifying keys fail the check:\n  {}",
            problems.join("\n  ")
        );
    }
    println!(
        "ok: {} production verifying keys, each pinned to one of this build's proving keys",
        markers.len()
    );
    if let Some(prover_url) = opts.prover_url {
        // The markers matched the same verifying keys, so a matching prover
        // proves with exactly the keys the program verifies against.
        let report = ProverClient::new(prover_url.clone())
            .check_proving_keys()
            .with_context(|| format!("prover {prover_url} failed the proving key check"))?;
        println!(
            "ok: prover {prover_url} ({}) serves the same proving keys",
            report.prefix
        );
    }
    Ok(())
}

/// This build's proving keys by sha256, named by key file.
fn known_keys() -> BTreeMap<[u8; 32], &'static str> {
    known_proving_keys()
        .map(|(name, sha256)| (sha256, name))
        .collect()
}

fn read_markers(source: &VksSourceOptions) -> Result<Vec<SetupTxt>> {
    let binary = match &source.so {
        Some(path) => {
            fs::read(path).with_context(|| format!("failed to read {}", path.display()))?
        }
        None => {
            let program_id = match &source.program_id {
                Some(program_id) => Address::from_str(program_id)
                    .map_err(|e| anyhow!("invalid --program-id {program_id}: {e}"))?,
                None => PROGRAM_ID_PUBKEY,
            };
            let config = CliConfigFile::load()?;
            let rpc_url = resolve_rpc_url(source.rpc_url.as_deref(), &config);
            read_program_elf(&SolanaRpc::new(rpc_url), &program_id)?
        }
    };
    find_setup_txts(&binary).map_err(|e| anyhow!("malformed verifying key setup marker: {e}"))
}

/// The ELF a loader-v3 program runs: its ProgramData account after the header,
/// the bytes `solana program dump` writes.
fn read_program_elf(rpc: &SolanaRpc, program_id: &Address) -> Result<Vec<u8>> {
    let program_data = get_program_data_address(program_id);
    let account = rpc
        .get_account(program_data)
        .with_context(|| format!("fetching ProgramData {program_data}"))?
        .ok_or_else(|| {
            anyhow!("ProgramData {program_data} of {program_id} not found; is it deployed?")
        })?;
    if account.owner != BPF_LOADER_UPGRADEABLE_PUBKEY {
        bail!("{program_data} is not owned by the upgradeable loader");
    }
    if account.data.get(..PROGRAM_DATA_TAG.len()) != Some(&PROGRAM_DATA_TAG[..]) {
        bail!("{program_data} is not a loader-v3 ProgramData account");
    }
    account
        .data
        .get(UpgradeableLoaderState::size_of_programdata_metadata()..)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("ProgramData {program_data} holds no program"))
}

fn list_line(marker: &SetupTxt, known: &BTreeMap<[u8; 32], &'static str>) -> String {
    let label = known
        .get(&marker.proving_key_sha256)
        .copied()
        .unwrap_or("unknown");
    format!(
        "{label:<34} insecure_test_setup={} proving_key_sha256={}",
        marker.insecure_test_setup,
        hex::encode(marker.proving_key_sha256)
    )
}

/// Every reason `markers` fail the check against `known`; empty when they pass.
fn check_markers(markers: &[SetupTxt], known: &BTreeMap<[u8; 32], &'static str>) -> Vec<String> {
    let mut problems = Vec::new();
    if markers.is_empty() {
        problems.push(
            "no verifying key setup markers: the program predates them or embeds no verifying keys"
                .to_string(),
        );
    }
    for marker in markers {
        let sha256 = hex::encode(marker.proving_key_sha256);
        let label = known.get(&marker.proving_key_sha256).copied();
        if marker.insecure_test_setup {
            problems.push(format!(
                "{} (proving key {sha256}) is an insecure test setup",
                label.unwrap_or("verifying key")
            ));
        }
        if label.is_none() {
            problems.push(format!(
                "verifying key for proving key {sha256} is not one of this build's"
            ));
        }
    }
    for (sha256, name) in known {
        if !markers
            .iter()
            .any(|marker| marker.proving_key_sha256 == *sha256)
        {
            problems.push(format!("{name} is missing from the program"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(sha256: [u8; 32], insecure_test_setup: bool) -> SetupTxt {
        SetupTxt {
            name: "VERIFYINGKEY".to_string(),
            insecure_test_setup,
            proving_key_sha256: sha256,
        }
    }

    fn known() -> BTreeMap<[u8; 32], &'static str> {
        BTreeMap::from([
            ([1; 32], "merge_8_1.key"),
            ([2; 32], "transfer_ring_2_2.key"),
        ])
    }

    #[test]
    fn a_production_build_of_every_known_key_passes() {
        let markers = [marker([2; 32], false), marker([1; 32], false)];
        assert_eq!(check_markers(&markers, &known()), Vec::<String>::new());
    }

    #[test]
    fn every_failure_is_reported() {
        let markers = [marker([1; 32], true), marker([9; 32], false)];
        let nines = hex::encode([9u8; 32]);
        let ones = hex::encode([1u8; 32]);
        assert_eq!(
            check_markers(&markers, &known()),
            vec![
                format!("merge_8_1.key (proving key {ones}) is an insecure test setup"),
                format!("verifying key for proving key {nines} is not one of this build's"),
                "transfer_ring_2_2.key is missing from the program".to_string(),
            ]
        );
    }

    #[test]
    fn a_binary_without_markers_fails() {
        assert_eq!(check_markers(&[], &known()).len(), 3);
    }

    #[test]
    fn list_labels_known_and_unknown_keys() {
        let known = known();
        assert_eq!(
            [
                list_line(&marker([1; 32], false), &known),
                list_line(&marker([9; 32], true), &known)
            ],
            [
                format!(
                    "{:<34} insecure_test_setup=false proving_key_sha256={}",
                    "merge_8_1.key",
                    hex::encode([1u8; 32])
                ),
                format!(
                    "{:<34} insecure_test_setup=true proving_key_sha256={}",
                    "unknown",
                    hex::encode([9u8; 32])
                ),
            ]
        );
    }

    /// The shielded-pool build passes the check it runs in the devnet deploy.
    #[test]
    fn the_built_shielded_pool_program_passes() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../target/deploy/shielded_pool_program.so"
        );
        let Ok(binary) = fs::read(path) else {
            eprintln!("skipping: {path} is not built (just build-programs)");
            return;
        };
        let markers = find_setup_txts(&binary).expect("markers parse");
        assert_eq!(check_markers(&markers, &known_keys()), Vec::<String>::new());
    }
}
