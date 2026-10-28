//! `zolana vks`: read the setup marker groth16-solana embeds next to every
//! verifying key, from any deployed program (upgradeable loader, loader-v4 or
//! the legacy BPF loaders) or a local `.so`. `check` fails on a binary without
//! markers or with an insecure test setup. `--expect` pins the keys a program
//! must embed from a manifest of its proving keys. For the shielded pool the
//! markers must be exactly this build's verifying keys, so a deployment that
//! passes verifies exactly the proving keys this build's prover and clients
//! pin.

use std::{collections::BTreeMap, fs, path::Path, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use groth16_solana::vk::setup::{find_setup_txts, SetupTxt};
use solana_address::Address;
use solana_loader_v3_interface::{get_program_data_address, state::UpgradeableLoaderState};
use solana_loader_v4_interface::state::LoaderV4State;
use solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4};
use spr_client::{
    prover::{known_proving_keys, redact_api_key},
    ProverClient, Rpc, SolanaRpc,
};
use spr_interface::PROGRAM_ID_PUBKEY;

use crate::{
    args::{VksCheckOptions, VksCommand, VksSourceOptions},
    cli_config::{resolve_rpc_url, CliConfigFile},
};

/// Loader-v3 `UpgradeableLoaderState::ProgramData` discriminant, little endian.
const PROGRAM_DATA_TAG: [u8; 4] = [3, 0, 0, 0];

/// Proving key file names by sha256.
type KeyNames = BTreeMap<[u8; 32], String>;

/// The verifying keys a checked program must embed beyond the setup checks.
enum Required<'a> {
    Nothing,
    /// Exactly this build's shielded-pool keys and no other.
    ShieldedPool(&'a KeyNames),
    /// Every key an `--expect` manifest lists. Other production keys may sit
    /// beside them, such as the shielded-pool markers every program linking
    /// `spr-interface` embeds.
    Listed(&'a KeyNames),
}

/// Where a loader keeps the ELF a program runs.
#[derive(Debug, PartialEq, Eq)]
enum ElfLocation {
    /// A separate ProgramData account, after its header (upgradeable loader).
    ProgramData,
    /// The program account itself from `offset`: after the loader-v4 header,
    /// or the whole account for the legacy BPF loaders.
    ProgramAccount { offset: usize },
}

pub(crate) fn run_vks(command: VksCommand) -> Result<()> {
    match command {
        VksCommand::List(opts) => {
            let expected = read_expected_keys(opts.expect.as_deref())?;
            let markers = read_markers(&opts.source)?;
            let names = key_names(expected.as_ref());
            for marker in &markers {
                println!("{}", list_line(marker, &names));
            }
            println!("{} verifying key(s)", markers.len());
            Ok(())
        }
        VksCommand::Check(opts) => run_check(opts),
    }
}

fn run_check(opts: VksCheckOptions) -> Result<()> {
    let mut problems = Vec::new();
    let shielded_pool = match requires_shielded_pool_keys(&opts) {
        Ok(required) => required,
        Err(error) => {
            problems.push(format!("{error:#}"));
            false
        }
    };
    let expected = match read_expected_keys(opts.expect.as_deref()) {
        Ok(expected) => expected,
        Err(error) => {
            problems.push(format!("{error:#}"));
            None
        }
    };
    let markers = match read_markers(&opts.source) {
        Ok(markers) => Some(markers),
        Err(error) => {
            problems.push(format!("{error:#}"));
            None
        }
    };
    let names = key_names(expected.as_ref());
    let pool_keys = shielded_pool_keys();
    let required = match (&expected, shielded_pool) {
        (Some(keys), _) => Required::Listed(keys),
        (None, true) => Required::ShieldedPool(&pool_keys),
        (None, false) => Required::Nothing,
    };
    if let Some(markers) = &markers {
        problems.extend(check_markers(markers, &names, &required));
    }
    let mut prover_report = Vec::new();
    if problems.is_empty() {
        if let Some(prover_url) = opts.prover_url {
            // Only compare prover keys once the program's key set matched.
            let shown = redact_api_key(&prover_url);
            let checked = (|| -> Result<()> {
                let prover = opts.tee.apply(ProverClient::new(prover_url))?;
                if prover.has_tee() {
                    let attested = prover
                        .attest()
                        .with_context(|| format!("prover {shown} failed TEE attestation"))?;
                    prover_report.push(format!("Prover {shown}: attests, {attested}"));
                }
                let report = prover
                    .check_proving_keys()
                    .with_context(|| format!("prover {shown} failed the proving key check"))?;
                prover_report.push(format!(
                    "Prover {shown} ({}): serves the same proving keys",
                    report.prefix
                ));
                Ok(())
            })();
            if let Err(error) = checked {
                problems.push(format!("{error:#}"));
            }
        }
    }
    for line in prover_report {
        println!("{line}");
    }
    print!(
        "{}",
        check_report(markers.as_deref(), &names, &required, &problems)
    );
    if !problems.is_empty() {
        bail!("verifying key check failed");
    }
    Ok(())
}

/// Always report what could be inspected before giving the overall result.
/// A missing or malformed marker never implies that test setups are absent.
fn check_report(
    markers: Option<&[SetupTxt]>,
    names: &KeyNames,
    required: &Required,
    problems: &[String],
) -> String {
    let mut lines = Vec::new();
    match markers {
        Some(markers) => {
            lines.push(format!("Verifying keys: {} found", markers.len()));
            for marker in markers {
                lines.push(format!("  {}: {}", marker.name, list_line(marker, names)));
            }
            if markers.is_empty() {
                lines.push("Test setup: unknown (no valid setup markers)".to_string());
            } else {
                let insecure = markers
                    .iter()
                    .filter(|marker| marker.insecure_test_setup)
                    .collect::<Vec<_>>();
                if insecure.is_empty() {
                    lines.push("Test setup: none found".to_string());
                } else {
                    lines.push(format!("Test setup: detected in {} key(s)", insecure.len()));
                    for marker in insecure {
                        lines.push(format!(
                            "  {}: proving_key_sha256={}",
                            names
                                .get(&marker.proving_key_sha256)
                                .map_or(marker.name.as_str(), String::as_str),
                            hex::encode(marker.proving_key_sha256)
                        ));
                    }
                }
            }
        }
        None => {
            lines.push("Verifying keys: unknown (inspection failed)".to_string());
            lines.push("Test setup: unknown (no valid setup markers)".to_string());
        }
    }
    match required {
        Required::Nothing => {}
        Required::Listed(keys) => lines.push(format!(
            "Expected keys: {} required from manifest",
            keys.len()
        )),
        Required::ShieldedPool(keys) => lines.push(format!(
            "Expected keys: exactly {} shielded-pool keys",
            keys.len()
        )),
    }
    if problems.is_empty() {
        lines.push("PASS: verifying key checks passed".to_string());
    } else {
        lines.push("FAIL: verifying key checks failed".to_string());
        lines.extend(problems.iter().map(|problem| format!("  - {problem}")));
    }
    format!("{}\n", lines.join("\n"))
}

/// This build's shielded-pool proving keys by sha256, named by key file.
fn shielded_pool_keys() -> KeyNames {
    known_proving_keys()
        .map(|(name, sha256)| (sha256, name.to_string()))
        .collect()
}

/// Names for every key this build or the `--expect` manifest knows; a
/// manifest name wins.
fn key_names(expected: Option<&KeyNames>) -> KeyNames {
    let mut names = shielded_pool_keys();
    if let Some(expected) = expected {
        names.extend(
            expected
                .iter()
                .map(|(sha256, name)| (*sha256, name.clone())),
        );
    }
    names
}

fn read_expected_keys(path: Option<&Path>) -> Result<Option<KeyNames>> {
    path.map(|path| {
        let manifest = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        parse_key_manifest(&manifest)
            .with_context(|| format!("invalid key manifest {}", path.display()))
    })
    .transpose()
}

/// The proving keys a sha256sum-style manifest lists: one `<sha256>  <file>`
/// per line, keeping the files that are proving keys (`*pk.bin`, `*.pk` or `*.key`).
/// A verifying key marker pins its proving key's sha256, so the manifest's
/// other files (such as `vk.bin`) have nothing to match.
fn parse_key_manifest(manifest: &str) -> Result<KeyNames> {
    let mut keys = KeyNames::new();
    for (index, line) in manifest.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_number = index + 1;
        let (digest, file) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| anyhow!("line {line_number}: expected `<sha256>  <file>`"))?;
        // sha256sum marks a file hashed in binary mode with a leading `*`.
        let file = file.trim_start().trim_start_matches('*');
        if !(file.ends_with("pk.bin") || file.ends_with(".pk") || file.ends_with(".key")) {
            continue;
        }
        let mut sha256 = [0u8; 32];
        hex::decode_to_slice(digest, &mut sha256)
            .map_err(|e| anyhow!("line {line_number}: invalid sha256 {digest}: {e}"))?;
        keys.insert(sha256, file.to_string());
    }
    if keys.is_empty() {
        bail!("it names no proving key (a *pk.bin, *.pk or *.key file)");
    }
    Ok(keys)
}

/// Whether the check requires exactly this build's shielded-pool keys: asked
/// for with `--shielded-pool`, or implied by reading the shielded-pool program
/// by id unless `--expect` names the keys instead. The prover check compares
/// against the same keys, so it needs this mode.
fn requires_shielded_pool_keys(opts: &VksCheckOptions) -> Result<bool> {
    let shielded_pool = opts.shielded_pool
        || (opts.expect.is_none()
            && opts.source.so.is_none()
            && deployed_program_id(&opts.source)? == PROGRAM_ID_PUBKEY);
    if opts.prover_url.is_some() && !shielded_pool {
        bail!("--prover-url checks the shielded-pool proving keys; pass --shielded-pool");
    }
    Ok(shielded_pool)
}

/// The deployed program read when no local binary is given.
fn deployed_program_id(source: &VksSourceOptions) -> Result<Address> {
    match &source.program_id {
        Some(program_id) => Address::from_str(program_id)
            .map_err(|e| anyhow!("invalid --program-id {program_id}: {e}")),
        None => Ok(PROGRAM_ID_PUBKEY),
    }
}

fn read_markers(source: &VksSourceOptions) -> Result<Vec<SetupTxt>> {
    let binary = match &source.so {
        Some(path) => {
            fs::read(path).with_context(|| format!("failed to read {}", path.display()))?
        }
        None => {
            let program_id = deployed_program_id(source)?;
            let config = CliConfigFile::load()?;
            let rpc_url = resolve_rpc_url(source.rpc_url.as_deref(), &config);
            read_program_elf(&SolanaRpc::new(rpc_url), &program_id)?
        }
    };
    find_setup_txts(&binary).map_err(|e| anyhow!("malformed verifying key setup marker: {e}"))
}

fn elf_location(program_id: &Address, owner: &Address) -> Result<ElfLocation> {
    if *owner == bpf_loader_upgradeable::ID {
        Ok(ElfLocation::ProgramData)
    } else if *owner == loader_v4::ID {
        Ok(ElfLocation::ProgramAccount {
            offset: LoaderV4State::program_data_offset(),
        })
    } else if *owner == bpf_loader::ID || *owner == bpf_loader_deprecated::ID {
        Ok(ElfLocation::ProgramAccount { offset: 0 })
    } else {
        bail!("{program_id} is owned by {owner}, not a program loader")
    }
}

/// The ELF a deployed program runs, the bytes `solana program dump` writes.
fn read_program_elf(rpc: &SolanaRpc, program_id: &Address) -> Result<Vec<u8>> {
    let program = rpc
        .get_account(*program_id)
        .with_context(|| format!("fetching program {program_id}"))?
        .ok_or_else(|| anyhow!("program {program_id} not found; is it deployed?"))?;
    match elf_location(program_id, &program.owner)? {
        ElfLocation::ProgramData => read_program_data_elf(rpc, program_id),
        ElfLocation::ProgramAccount { offset } => {
            program_account_elf(program_id, &program.data, offset)
        }
    }
}

fn program_account_elf(program_id: &Address, data: &[u8], offset: usize) -> Result<Vec<u8>> {
    data.get(offset..)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("program {program_id} holds no program"))
}

/// An upgradeable-loader program's ProgramData account after its header.
fn read_program_data_elf(rpc: &SolanaRpc, program_id: &Address) -> Result<Vec<u8>> {
    let program_data = get_program_data_address(program_id);
    let account = rpc
        .get_account(program_data)
        .with_context(|| format!("fetching ProgramData {program_data}"))?
        .ok_or_else(|| {
            anyhow!("ProgramData {program_data} of {program_id} not found; is it deployed?")
        })?;
    if account.owner != bpf_loader_upgradeable::ID {
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

fn list_line(marker: &SetupTxt, names: &KeyNames) -> String {
    let label = names
        .get(&marker.proving_key_sha256)
        .map_or("unknown", String::as_str);
    format!(
        "{label:<34} insecure_test_setup={} proving_key_sha256={}",
        marker.insecure_test_setup,
        hex::encode(marker.proving_key_sha256)
    )
}

/// Every reason `markers` fail the check; empty when they pass. Any program
/// fails without markers or with an insecure test setup, and must embed the
/// keys `required` names.
fn check_markers(markers: &[SetupTxt], names: &KeyNames, required: &Required) -> Vec<String> {
    let mut problems = Vec::new();
    if markers.is_empty() {
        problems.push(
            "no verifying key setup markers: the program predates them or embeds no verifying keys"
                .to_string(),
        );
    }
    for marker in markers {
        let sha256 = hex::encode(marker.proving_key_sha256);
        if marker.insecure_test_setup {
            problems.push(format!(
                "{} (proving key {sha256}) is an insecure test setup",
                names
                    .get(&marker.proving_key_sha256)
                    .map_or("verifying key", String::as_str)
            ));
        }
        if let Required::ShieldedPool(keys) = required {
            if !keys.contains_key(&marker.proving_key_sha256) {
                problems.push(format!(
                    "verifying key for proving key {sha256} is not one of this build's"
                ));
            }
        }
    }
    let required_keys = match required {
        Required::Nothing => return problems,
        Required::ShieldedPool(keys) | Required::Listed(keys) => keys,
    };
    for (sha256, name) in required_keys.iter() {
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
    use crate::args::ProverTeeOptions;

    fn marker(sha256: [u8; 32], insecure_test_setup: bool) -> SetupTxt {
        SetupTxt {
            name: "VERIFYINGKEY".to_string(),
            insecure_test_setup,
            proving_key_sha256: sha256,
        }
    }

    fn keys(entries: &[([u8; 32], &str)]) -> KeyNames {
        entries
            .iter()
            .map(|(sha256, name)| (*sha256, name.to_string()))
            .collect()
    }

    fn known() -> KeyNames {
        keys(&[
            ([1; 32], "merge_24_1.key"),
            ([2; 32], "transfer_ring_2_2.key"),
        ])
    }

    fn check_options(
        program_id: Option<String>,
        so: Option<&str>,
        shielded_pool: bool,
        expect: Option<&str>,
        prover_url: Option<&str>,
    ) -> VksCheckOptions {
        VksCheckOptions {
            source: VksSourceOptions {
                program_id,
                so: so.map(std::path::PathBuf::from),
                rpc_url: None,
            },
            shielded_pool,
            expect: expect.map(std::path::PathBuf::from),
            prover_url: prover_url.map(str::to_string),
            tee: ProverTeeOptions::default(),
        }
    }

    #[test]
    fn check_reports_keys_test_status_and_pass() {
        let markers = [marker([1; 32], false)];
        let report = check_report(Some(&markers), &known(), &Required::Nothing, &[]);
        assert_eq!(
            (
                report.contains("Verifying keys: 1 found"),
                report.contains("merge_24_1.key"),
                report.contains("Test setup: none found"),
                report.contains("PASS: verifying key checks passed")
            ),
            (true, true, true, true)
        );
    }

    #[test]
    fn check_reports_each_test_key_and_all_failure_reasons() {
        let markers = [marker([1; 32], true), marker([9; 32], true)];
        let names = known();
        let required = Required::ShieldedPool(&names);
        let problems = check_markers(&markers, &names, &required);
        let report = check_report(Some(&markers), &names, &required, &problems);
        assert_eq!(
            (
                report.contains("Verifying keys: 2 found"),
                report.contains("Test setup: detected in 2 key(s)"),
                report.contains(&format!(
                    "merge_24_1.key: proving_key_sha256={}",
                    hex::encode([1; 32])
                )),
                report.contains(&format!(
                    "VERIFYINGKEY: proving_key_sha256={}",
                    hex::encode([9; 32])
                )),
                report.contains("FAIL: verifying key checks failed"),
                problems.iter().all(|problem| report.contains(problem))
            ),
            (true, true, true, true, true, true)
        );
    }

    #[test]
    fn no_markers_or_failed_inspection_report_unknown_test_status() {
        for markers in [None, Some([].as_slice())] {
            let report = check_report(
                markers,
                &known(),
                &Required::Nothing,
                &["cannot verify keys".into()],
            );
            assert_eq!(
                (
                    report.contains("Test setup: unknown (no valid setup markers)"),
                    report.contains("FAIL:"),
                    report.contains("cannot verify keys"),
                    report.contains("Test setup: none found")
                ),
                (true, true, true, false)
            );
        }
    }

    #[test]
    fn manifest_mismatch_reports_clean_test_status_and_failure() {
        let names = known();
        let required = Required::Listed(&names);
        let markers = [marker([1; 32], false)];
        let problems = check_markers(&markers, &names, &required);
        let report = check_report(Some(&markers), &names, &required, &problems);
        assert_eq!(
            (
                report.contains("Test setup: none found"),
                report.contains("Expected keys: 2 required from manifest"),
                report.contains("transfer_ring_2_2.key is missing"),
                report.contains("FAIL:")
            ),
            (true, true, true, true)
        );
    }

    #[test]
    fn manifest_accepts_dsl_proving_key_files() {
        let manifest = format!("{}  increment.pk\n", hex::encode([3; 32]));
        assert_eq!(
            parse_key_manifest(&manifest).unwrap(),
            keys(&[([3; 32], "increment.pk")])
        );
    }

    #[test]
    fn a_production_build_of_every_known_key_passes() {
        let known = known();
        let markers = [marker([2; 32], false), marker([1; 32], false)];
        assert_eq!(
            check_markers(&markers, &known, &Required::ShieldedPool(&known)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn every_failure_is_reported() {
        let known = known();
        let markers = [marker([1; 32], true), marker([9; 32], false)];
        let nines = hex::encode([9u8; 32]);
        let ones = hex::encode([1u8; 32]);
        assert_eq!(
            check_markers(&markers, &known, &Required::ShieldedPool(&known)),
            vec![
                format!("merge_24_1.key (proving key {ones}) is an insecure test setup"),
                format!("verifying key for proving key {nines} is not one of this build's"),
                "transfer_ring_2_2.key is missing from the program".to_string(),
            ]
        );
    }

    #[test]
    fn a_binary_without_markers_fails() {
        let known = known();
        assert_eq!(
            check_markers(&[], &known, &Required::ShieldedPool(&known)).len(),
            3
        );
    }

    #[test]
    fn any_program_passes_with_production_keys_of_its_own() {
        let markers = [marker([9; 32], false), marker([1; 32], false)];
        assert_eq!(
            check_markers(&markers, &known(), &Required::Nothing),
            Vec::<String>::new()
        );
    }

    #[test]
    fn any_program_fails_on_an_insecure_test_setup() {
        let markers = [marker([9; 32], true), marker([1; 32], false)];
        assert_eq!(
            check_markers(&markers, &known(), &Required::Nothing),
            vec![format!(
                "verifying key (proving key {}) is an insecure test setup",
                hex::encode([9u8; 32])
            )]
        );
    }

    #[test]
    fn any_program_fails_without_markers() {
        assert_eq!(check_markers(&[], &known(), &Required::Nothing).len(), 1);
    }

    #[test]
    fn listed_keys_must_all_be_embedded_beside_any_other_production_keys() {
        let listed = keys(&[([7; 32], "make_pk.bin"), ([8; 32], "take_pk.bin")]);
        let mut names = known();
        names.extend(listed.clone());
        let markers = [
            marker([7; 32], true),
            marker([1; 32], false),
            marker([9; 32], false),
        ];
        assert_eq!(
            check_markers(&markers, &names, &Required::Listed(&listed)),
            vec![
                format!(
                    "make_pk.bin (proving key {}) is an insecure test setup",
                    hex::encode([7u8; 32])
                ),
                "take_pk.bin is missing from the program".to_string(),
            ]
        );
    }

    #[test]
    fn a_key_manifest_lists_its_proving_keys() {
        let make = hex::encode([7u8; 32]);
        let make_vk = hex::encode([6u8; 32]);
        let take = hex::encode([8u8; 32]);
        let merge = hex::encode([1u8; 32]);
        let manifest = format!(
            "{make}  make_pk.bin\n{make_vk}  make_vk.bin\n\n{take} *build/gnark/take/pk.bin\n{merge}  merge_24_1.key\n"
        );
        assert_eq!(
            parse_key_manifest(&manifest).expect("manifest"),
            keys(&[
                ([7; 32], "make_pk.bin"),
                ([8; 32], "build/gnark/take/pk.bin"),
                ([1; 32], "merge_24_1.key"),
            ])
        );
    }

    #[test]
    fn a_key_manifest_rejects_malformed_lines_and_a_missing_proving_key() {
        let vk_only = format!("{}  make_vk.bin\n", hex::encode([6u8; 32]));
        let errors = [
            "zz  make_pk.bin\n".to_string(),
            "make_pk.bin\n".to_string(),
            vk_only,
        ]
        .map(|manifest| {
            parse_key_manifest(&manifest)
                .expect_err("invalid manifest")
                .to_string()
        });
        assert_eq!(
            errors,
            [
                "line 1: invalid sha256 zz: Invalid string length".to_string(),
                "line 1: expected `<sha256>  <file>`".to_string(),
                "it names no proving key (a *pk.bin, *.pk or *.key file)".to_string(),
            ]
        );
    }

    #[test]
    fn the_shielded_pool_key_set_is_required_for_its_program_id_or_on_request() {
        let spp = Some(PROGRAM_ID_PUBKEY.to_string());
        let other = Some(Address::new_from_array([7; 32]).to_string());
        let cases = [
            (check_options(None, None, false, None, None), true),
            (check_options(spp.clone(), None, false, None, None), true),
            (
                check_options(spp, None, false, Some("keys.CHECKSUM"), None),
                false,
            ),
            (check_options(other.clone(), None, false, None, None), false),
            (check_options(other, None, true, None, None), true),
            (
                check_options(None, Some("program.so"), false, None, None),
                false,
            ),
            (
                check_options(None, Some("program.so"), true, None, None),
                true,
            ),
        ];
        for (opts, shielded_pool) in cases {
            assert_eq!(
                requires_shielded_pool_keys(&opts).expect("mode"),
                shielded_pool,
                "{opts:?}"
            );
        }
    }

    #[test]
    fn the_prover_check_needs_the_shielded_pool_key_set() {
        let opts = check_options(
            None,
            Some("program.so"),
            false,
            None,
            Some("http://127.0.0.1:3001"),
        );
        assert_eq!(
            requires_shielded_pool_keys(&opts)
                .expect_err("prover check without the key set")
                .to_string(),
            "--prover-url checks the shielded-pool proving keys; pass --shielded-pool"
        );
    }

    #[test]
    fn every_program_loader_is_read() {
        let program_id = Address::new_from_array([5; 32]);
        let locations = [
            bpf_loader_upgradeable::ID,
            loader_v4::ID,
            bpf_loader::ID,
            bpf_loader_deprecated::ID,
        ]
        .map(|owner| elf_location(&program_id, &owner).expect("a program loader"));
        assert_eq!(
            locations,
            [
                ElfLocation::ProgramData,
                ElfLocation::ProgramAccount { offset: 48 },
                ElfLocation::ProgramAccount { offset: 0 },
                ElfLocation::ProgramAccount { offset: 0 },
            ]
        );
        assert_eq!(
            elf_location(&program_id, &solana_sdk_ids::system_program::ID)
                .expect_err("not a loader")
                .to_string(),
            format!(
                "{program_id} is owned by {}, not a program loader",
                solana_sdk_ids::system_program::ID
            )
        );
    }

    #[test]
    fn a_loader_v4_program_runs_the_bytes_after_its_header() {
        let program_id = Address::new_from_array([5; 32]);
        let mut data = vec![0u8; LoaderV4State::program_data_offset()];
        data.extend_from_slice(b"\x7fELF");
        assert_eq!(
            program_account_elf(&program_id, &data, LoaderV4State::program_data_offset())
                .expect("elf"),
            b"\x7fELF".to_vec()
        );
        assert!(program_account_elf(&program_id, &[0u8; 4], 48).is_err());
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
                    "merge_24_1.key",
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
        let keys = shielded_pool_keys();
        assert_eq!(
            check_markers(&markers, &keys, &Required::ShieldedPool(&keys)),
            Vec::<String>::new()
        );
    }
}
