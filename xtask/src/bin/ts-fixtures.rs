use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    thread,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use solana_address::Address;
use zolana_client::{
    prover::{CompressedCommitments, ProofCompressed, TransferInput, TransferInputs},
    Context as RpcContext, MerkleContext, MerkleProof, NonInclusionProof, ProverClient,
};
use zolana_interface::instruction::{builders::Deposit, tag};
use zolana_program_test::TestIndexer;
use zolana_test_utils::smart_account::{standard_accounts, StandardSigners};
use zolana_transaction::{
    derive_blinding, instructions::transact::canonical_shape, AssetRegistry, Data, DataRecord,
};

/// Single source of truth for the historical fixture baseline commit. Pins the
/// 182-path `sdk-libs` inventory, `docs/spec.md`, and the proving-key lockfile.
/// Generators and TypeScript checks read this path; do not copy the SHA.
const HISTORICAL_BASELINE_COMMIT_PATH: &str = "sdk-libs/ts/config/historical-baseline-commit";
/// Provenance the manifest records: the revision each family of fixtures was
/// last regenerated against. These stamp the output; they do not gate it.
/// `--check` regenerates fixture bodies from the working tree and compares
/// them to the committed files. Live client stamps advance only when a
/// current-client fixture body changes, so an unrelated edit under
/// `sdk-libs/client/src` cannot fail the gate or dirty the tree.
const BASELINE_SHA: &str = "8ce9897ccd7de06ef924b9cfb90c8d4a45451b71";
const INTERFACE_SHA: &str = "8ce9897ccd7de06ef924b9cfb90c8d4a45451b71";
const MERKLE_SHA: &str = "4d9a39f17c709c1dcb0ec9f5caf6b0ab935ecffa";
const FIXTURE_SCHEMA: &str = "zolana-ts-fixtures-v1";
const GENERATOR_COMMAND: &str = "rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures";
const EXPECTED_FIXTURE_COUNT: usize = 58;
const INVENTORY_FILES: [&str; 6] = [
    "sdk-libs/ts/inventory/inventory-client.md",
    "sdk-libs/ts/inventory/inventory-wallet.md",
    "sdk-libs/ts/inventory/inventory-transaction.md",
    "sdk-libs/ts/inventory/inventory-keypair.md",
    "sdk-libs/ts/inventory/inventory-support.md",
    "sdk-libs/ts/inventory/inventory-indexer-and-smart-account.md",
];
const FIXTURE_DIRS: [&str; 11] = [
    "interface",
    "keypair",
    "transaction",
    "indexer-api",
    "api",
    "client",
    "wallet",
    "merkle-tree",
    "smart-account-client",
    "test-kit",
    "workflows",
];

#[derive(Debug, Clone)]
struct InventoryRow {
    path: String,
    marker: String,
    disposition: String,
    target: String,
    responsibility: String,
    fixture: String,
    tests: String,
    packet: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ts-fixtures failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut check = false;
    let mut current_client = false;
    let mut reports_only = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--current-client" => current_client = true,
            "--reports-only" => reports_only = true,
            "--help" | "-h" => {
                println!(
                    "Generate and verify deterministic TypeScript conformance fixtures.\n\nusage: cargo run -p xtask --bin ts-fixtures -- [--check] [--current-client] [--reports-only]"
                );
                return Ok(());
            }
            _ => bail!("unexpected argument {arg:?}"),
        }
    }
    let root = workspace_root()?;
    if current_client {
        return generate_current_client_fixtures(&root, check);
    }
    let baseline = historical_baseline_commit(&root)?;
    // The reports are a pure function of the inventory tables, so they can be
    // regenerated without the full fixture run behind them.
    if reports_only {
        let inventory = inventory(&root)?;
        let out = root.join("sdk-libs/ts");
        write_inventory_report(&out.join("reports/inventory.json"), &inventory, &baseline)?;
        write_packet_report(&out, &inventory, &baseline)?;
        stamp_packet_frozen_commits(&out.join("reports/packets"), &baseline)?;
        println!("regenerated reports for {} inventory rows", inventory.len());
        return Ok(());
    }
    let inventory = inventory(&root)?;

    if check {
        let generated = root.join("target/ts-fixtures-check");
        if generated.exists() {
            fs::remove_dir_all(&generated)?;
        }
        generate(&root, &generated, &inventory, &baseline)?;
        compare_outputs(&generated, &root.join("sdk-libs/ts"))?;
        fs::remove_dir_all(&generated)?;
        println!(
            "verified {} fixtures and {} inventory rows",
            EXPECTED_FIXTURE_COUNT,
            inventory.len()
        );
    } else {
        let out = root.join("sdk-libs/ts");
        generate(&root, &out, &inventory, &baseline)?;
        stamp_packet_frozen_commits(&out.join("reports/packets"), &baseline)?;
        println!(
            "generated {} fixtures and {} inventory rows",
            EXPECTED_FIXTURE_COUNT,
            inventory.len()
        );
    }
    Ok(())
}

fn generate_current_client_fixtures(root: &Path, check: bool) -> Result<()> {
    let fixtures_root = root.join("sdk-libs/ts/fixtures");
    let vectors = production_client_vectors(root)?;
    let (fixtures, revision) = stamp_current_client(
        client_fixtures(root, &vectors)?,
        &current_client_revision(root)?,
        &fixtures_root,
    )?;
    let fixtures = fixtures
        .into_iter()
        .filter(|(path, _)| CURRENT_CLIENT_FIXTURES.contains(path))
        .collect::<Vec<_>>();

    if check {
        for (path, expected) in &fixtures {
            let actual: Value = serde_json::from_slice(&fs::read(fixtures_root.join(path))?)?;
            if actual != *expected {
                bail!("current client fixture differs: {path}");
            }
        }
        verify_current_client_manifest(&fixtures_root, &revision, &fixtures)?;
        println!("verified {} current client fixtures", fixtures.len());
        return Ok(());
    }

    for (path, fixture) in &fixtures {
        write_json(&fixtures_root.join(path), fixture)?;
    }
    let manifest_path = fixtures_root.join("manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["canonicalSourceRevisions"]["client"] = Value::String(revision.clone());
    let entries = manifest["files"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("manifest files is not an array"))?;
    for (path, _) in &fixtures {
        let bytes = fs::read(fixtures_root.join(path))?;
        let entry = entries
            .iter_mut()
            .find(|entry| entry["path"] == *path)
            .ok_or_else(|| anyhow::anyhow!("manifest lacks {path}"))?;
        entry["sha256"] = Value::String(sha256(&bytes));
    }
    write_json(&manifest_path, &manifest)?;
    println!("generated {} current client fixtures", fixtures.len());
    Ok(())
}

/// The three client fixtures that track live `sdk-libs/client` behavior rather
/// than a frozen baseline, because the client is under active review. Their
/// `sourceRevision` is informational: it records the git revision last used
/// when a body changed. Drift detection is body regeneration under `--check`.
const CURRENT_CLIENT_FIXTURES: [&str; 3] = [
    "client/errors-v1.json",
    "client/lib.json",
    "client/rpc-indexer-v1.json",
];

fn current_client_revision(root: &Path) -> Result<String> {
    // Directory tip for reviewers; not a gate input. Stamps advance only when
    // a current-client fixture body changes (see `stamp_current_client`).
    let revision = command_text(
        root,
        "git",
        &["log", "-1", "--format=%H", "--", "sdk-libs/client/src"],
    )?;
    Ok(revision.trim().to_string())
}

fn stamp_current_client(
    fixtures: Vec<(&'static str, Value)>,
    git_revision: &str,
    committed_fixtures: &Path,
) -> Result<(Vec<(&'static str, Value)>, String)> {
    let body_changed = CURRENT_CLIENT_FIXTURES.iter().any(|path| {
        let Some((_, generated)) = fixtures.iter().find(|(candidate, _)| candidate == path) else {
            return true;
        };
        match fs::read(committed_fixtures.join(path)) {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(committed) => fixture_body(&committed) != fixture_body(generated),
                Err(_) => true,
            },
            Err(_) => true,
        }
    });
    let revision = if body_changed {
        git_revision.to_string()
    } else {
        committed_client_revision(committed_fixtures)?.unwrap_or_else(|| git_revision.to_string())
    };
    let stamped = fixtures
        .into_iter()
        .map(|(path, mut fixture)| {
            if CURRENT_CLIENT_FIXTURES.contains(&path) {
                fixture["sourceRevision"] = Value::String(revision.clone());
            }
            (path, fixture)
        })
        .collect();
    Ok((stamped, revision))
}

/// Fixture JSON without the live provenance stamp. Body equality is what the
/// gate enforces for current-client fixtures.
fn fixture_body(fixture: &Value) -> Value {
    let mut body = fixture.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("sourceRevision");
    }
    body
}

fn committed_client_revision(committed_fixtures: &Path) -> Result<Option<String>> {
    let path = committed_fixtures.join(CURRENT_CLIENT_FIXTURES[0]);
    let Ok(bytes) = fs::read(&path) else {
        return Ok(None);
    };
    let fixture: Value = serde_json::from_slice(&bytes)?;
    Ok(fixture["sourceRevision"]
        .as_str()
        .filter(|revision| revision.len() == 40 && revision.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_string))
}

fn verify_current_client_manifest(
    fixtures_root: &Path,
    revision: &str,
    fixtures: &[(&str, Value)],
) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&fs::read(fixtures_root.join("manifest.json"))?)?;
    if manifest["canonicalSourceRevisions"]["client"] != revision {
        bail!("manifest client revision differs");
    }
    for (path, _) in fixtures {
        let entry = manifest["files"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["path"] == *path))
            .ok_or_else(|| anyhow::anyhow!("manifest lacks {path}"))?;
        let bytes = fs::read(fixtures_root.join(path))?;
        if entry["sha256"] != sha256(&bytes) {
            bail!("manifest hash mismatch for {path}");
        }
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("run git rev-parse")?;
    if !output.status.success() {
        bail!("not in a git worktree");
    }
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}

/// Load the historical baseline commit from [`HISTORICAL_BASELINE_COMMIT_PATH`].
fn historical_baseline_commit(root: &Path) -> Result<String> {
    let path = root.join(HISTORICAL_BASELINE_COMMIT_PATH);
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let sha = raw.trim();
    if sha.len() != 40 || !sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!(
            "{HISTORICAL_BASELINE_COMMIT_PATH} must contain one 40-char lowercase hex commit SHA"
        );
    }
    Ok(sha.to_string())
}

fn inventory(root: &Path) -> Result<Vec<InventoryRow>> {
    let baseline = historical_baseline_commit(root)?;
    let frozen_paths = command_lines(
        root,
        &["ls-tree", "-r", "--name-only", &baseline, "sdk-libs"],
    )?;
    if frozen_paths.len() != 182 {
        bail!(
            "frozen sdk-libs tree has {} paths, expected 182",
            frozen_paths.len()
        );
    }
    let frozen = frozen_paths.into_iter().collect::<BTreeSet<_>>();
    let mut rows = Vec::new();
    for file in INVENTORY_FILES {
        let text = fs::read_to_string(root.join(file)).with_context(|| format!("read {file}"))?;
        let lines = text.lines().collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            let (marker, path) = if let Some(path) = marker_path(line, "inventory-active") {
                ("active", path)
            } else if let Some(path) = marker_path(line, "inventory-exclusion") {
                ("exclusion", path)
            } else {
                continue;
            };
            let row_line = lines
                .get(index + 1)
                .ok_or_else(|| anyhow::anyhow!("{file}: marker for {path} has no row"))?;
            let cells = row_line
                .split('|')
                .skip(1)
                .take_while(|cell| !cell.trim().is_empty() || row_line.ends_with('|'))
                .map(|cell| cell.trim().to_string())
                .collect::<Vec<_>>();
            if cells.len() < 10 {
                bail!("{file}: malformed inventory row for {path}");
            }
            let row_path = cells[0]
                .strip_prefix("[`")
                .and_then(|cell| cell.split_once("`]("))
                .map_or_else(|| cells[0].trim_matches('`'), |(path, _)| path);
            if row_path != path {
                bail!("{file}: marker path {path} does not match row path {row_path}");
            }
            let packet = cells[9].trim_matches('`').to_string();
            if !matches!(
                packet.as_str(),
                "P00"
                    | "P01"
                    | "P03"
                    | "P04"
                    | "P05"
                    | "P06"
                    | "P07"
                    | "P08"
                    | "P09"
                    | "P10"
                    | "P11"
            ) {
                bail!("{file}: unknown packet {packet} for {path}");
            }
            let disposition = cells[1].trim_matches('`').to_string();
            if marker == "exclusion" && disposition != "not applicable" {
                bail!("{file}: exclusion {path} is not marked not applicable");
            }
            if marker == "active" && disposition == "not applicable" {
                bail!("{file}: active row {path} is marked not applicable");
            }
            rows.push(InventoryRow {
                path,
                marker: marker.to_string(),
                disposition,
                target: cells[2].clone(),
                responsibility: cells[3].clone(),
                fixture: cells[7].clone(),
                tests: cells[8].clone(),
                packet,
            });
        }
    }
    let mut counts = BTreeMap::<String, usize>::new();
    for row in &rows {
        *counts.entry(row.path.clone()).or_default() += 1;
        if row.fixture.is_empty() || row.tests.is_empty() {
            bail!("{} lacks fixture or test responsibility", row.path);
        }
    }
    let duplicates = counts
        .iter()
        .filter(|(_, count)| **count != 1)
        .map(|(path, count)| format!("{path} ({count})"))
        .collect::<Vec<_>>();
    if !duplicates.is_empty() {
        bail!("duplicate inventory rows: {}", duplicates.join(", "));
    }
    let covered = counts.keys().cloned().collect::<BTreeSet<_>>();
    let missing = frozen.difference(&covered).cloned().collect::<Vec<_>>();
    let extra = covered.difference(&frozen).cloned().collect::<Vec<_>>();
    if !missing.is_empty() || !extra.is_empty() || rows.len() != 182 {
        bail!(
            "inventory mismatch: {} rows, missing {:?}, extra {:?}",
            rows.len(),
            missing,
            extra
        );
    }
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(rows)
}

fn marker_path(line: &str, marker: &str) -> Option<String> {
    let prefix = format!("<!-- {marker}: ");
    line.strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(" -->"))
        .map(str::to_string)
}

fn generate(root: &Path, out: &Path, inventory: &[InventoryRow], baseline: &str) -> Result<()> {
    let fixtures = out.join("fixtures");
    for dir in FIXTURE_DIRS {
        fs::create_dir_all(fixtures.join(dir))?;
    }
    fs::create_dir_all(out.join("reports/packets"))?;

    let (records, client_revision) = production_fixtures(root, baseline)?;
    if records.len() != EXPECTED_FIXTURE_COUNT {
        bail!(
            "generated {} fixtures, expected {EXPECTED_FIXTURE_COUNT}",
            records.len()
        );
    }
    for (relative, record) in records {
        write_json(&fixtures.join(relative), &record)?;
    }
    write_inventory_report(&out.join("reports/inventory.json"), inventory, baseline)?;
    write_manifest(root, &fixtures, &client_revision, baseline)?;
    verify_manifest(&fixtures, &client_revision, baseline)?;
    write_packet_report(out, inventory, baseline)?;
    Ok(())
}

macro_rules! fixture_base {
    (
        $id:expr,
        $rust_path:expr,
        $symbol:expr,
        $inventory_row:expr,
        $packet:expr,
        $responsibility:expr,
        $inputs:expr,
        $expected:expr $(,)?
    ) => {
        json!({
            "expected": $expected,
            "id": $id,
            "inputs": $inputs,
            "inventoryRow": $inventory_row,
            "owningPacket": $packet,
            "responsibility": $responsibility,
            "rustPath": $rust_path,
            "rustSymbol": $symbol,
            "schema": FIXTURE_SCHEMA,
            "version": "1"
        })
    };
}

fn production_fixtures(
    root: &Path,
    baseline: &str,
) -> Result<(Vec<(&'static str, Value)>, String)> {
    let tree = Address::new_from_array([1; 32]);
    let depositor = Address::new_from_array([2; 32]);
    let deposit = Deposit {
        tree,
        depositor,
        spl: None,
        view_tag: [3; 32],
        owner: [4; 32],
        blinding: [5; 31],
        amount: 42,
        utxo_data: None,
        memo: Some(b"fixture".to_vec()),
    }
    .instruction();
    let deposit_expected = instruction_json(&deposit);

    let blinding_seed = [7u8; 31];
    let blindings = [0u8, 1, 255]
        .into_iter()
        .map(|position| {
            json!({
                "bytes": hex(&derive_blinding(&blinding_seed, position)),
                "position": position.to_string()
            })
        })
        .collect::<Vec<_>>();

    let shape = canonical_shape(2, 3)?;
    let shape_error = canonical_shape(99, 99).expect_err("unsupported shape");
    let duplicate_error = Data::new(vec![DataRecord::Memo(vec![1]), DataRecord::Memo(vec![2])])
        .validate()
        .expect_err("duplicate data");
    let canonical_data = Data::new(vec![
        DataRecord::ZoneData(vec![1]),
        DataRecord::UtxoData(vec![2, 3]),
        DataRecord::Memo(vec![4]),
    ]);
    canonical_data.validate()?;

    let (dummy, dummy_nullifier) =
        TransferInput::new_dummy(&[8; 31], &[9; 32], &[10; 32], &[11; 32])?;

    let compressed = ProofCompressed {
        a: [12; 32],
        b: [13; 64],
        c: [14; 32],
        commitment: Some(CompressedCommitments {
            commitment: [15; 32],
            commitment_pok: [16; 32],
        }),
    };
    let p256 = compressed.to_p256_proof()?;
    let missing_commitment_error = ProofCompressed {
        commitment: None,
        ..compressed
    }
    .to_p256_proof()
    .expect_err("commitment required");

    let indexer = TestIndexer::new();
    let indexer_root = indexer.root();
    let merkle = MerkleProof {
        leaf: [17; 32],
        merkle_context: MerkleContext {
            tree_type: 1,
            tree: Address::new_from_array([18; 32]),
        },
        path: vec![[19; 32]; 32],
        leaf_index: 7,
        root: [20; 32],
        root_seq: 8,
        root_index: 9,
    };
    let non_inclusion = NonInclusionProof {
        leaf: [21; 32],
        merkle_context: merkle.merkle_context.clone(),
        path: vec![[22; 32]; 40],
        low_element: [23; 32],
        low_element_index: 2,
        high_element: [24; 32],
        high_element_index: 3,
        root: [25; 32],
        root_seq: 10,
        root_index: 11,
    };
    let context = RpcContext { block_time: 1234 };

    let creator = Address::new_from_array([26; 32]);
    let accounts = standard_accounts();
    let smart_ixs = accounts.create_ixs(
        &creator,
        StandardSigners {
            protocol: Address::new_from_array([27; 32]),
            forester: Address::new_from_array([28; 32]),
            merge: Address::new_from_array([29; 32]),
            tree: Address::new_from_array([30; 32]),
            zone: Address::new_from_array([31; 32]),
        },
    );

    let mut registry = AssetRegistry::default();
    let mint = Address::new_from_array([32; 32]);
    registry.insert(2, mint)?;
    let reserved_error = registry
        .insert(1, Address::new_from_array([33; 32]))
        .expect_err("reserved SOL asset id");

    let transfer_inputs = TransferInputs {
        inputs: vec![dummy.clone()],
        outputs: vec![],
        external_data_hash: dummy.is_dummy.clone(),
        private_tx_hash: dummy.is_dummy.clone(),
        public_sol_amount: dummy.is_dummy.clone(),
        public_spl_amount: dummy.is_dummy.clone(),
        public_spl_asset_pubkey: dummy.is_dummy.clone(),
        zone_program_id: dummy.is_dummy.clone(),
        payer_pubkey_hash: dummy.is_dummy.clone(),
        public_input_hash: dummy.is_dummy.clone(),
    };
    let (prover_request, prover_result_error) = capture_prover_request(&transfer_inputs)?;
    let merkle_vectors = production_merkle_vectors(root)?;
    let keypair_vectors = production_keypair_vectors(root)?;
    let transaction_vectors = production_transaction_vectors(root)?;
    let api_vectors = production_api_vectors(root)?;
    let client_vectors = production_client_vectors(root)?;
    let wallet_vectors = production_wallet_vectors(root)?;

    let mut fixtures = vec![
        (
            "interface/deposit-instruction-v1.json",
            fixture_base!(
                "fx-p00-interface-deposit-v1",
                "program-libs/interface/src/instruction/builders/deposit.rs",
                "Deposit::instruction",
                "non-inventoried interface fixture responsibility",
                "P00",
                "exact instruction program, accounts, flags, and bytes",
                json!({
                    "amount":"42",
                    "blindingBytes":hex(&[5;31]),
                    "memoBytes":hex(b"fixture"),
                    "ownerBytes":hex(&[4;32]),
                    "testOnlySecret":true,
                    "viewTagBytes":hex(&[3;32])
                }),
                deposit_expected.clone(),
            ),
        ),
        (
            "keypair/test-secret-blinding-v1.json",
            fixture_base!(
                "fx-p00-keypair-test-secret-v1",
                "sdk-libs/transaction/src/utxo.rs",
                "derive_blinding",
                "sdk-libs/keypair/tests/steps/mod.rs",
                "P00",
                "fixed test secret marking and deterministic derived bytes",
                json!({"seedBytes":hex(&blinding_seed),"testOnlySecret":true}),
                json!({"blindings":blindings}),
            ),
        ),
        (
            "transaction/values-and-errors-v1.json",
            fixture_base!(
                "fx-p00-transaction-values-errors-v1",
                "sdk-libs/transaction/src/instructions/transact/shape.rs",
                "canonical_shape; Data::validate",
                "sdk-libs/transaction/tests/steps/mod.rs",
                "P00",
                "logical values and typed error evidence",
                json!({"inputs":"2","outputs":"3"}),
                json!({
                    "canonicalData":{"memoBytes":hex(canonical_data.memo().unwrap()),"valid":true},
                    "errors":[error_json(&shape_error),error_json(&duplicate_error)],
                    "shape":{"inputs":shape.n_inputs().to_string(),"outputs":shape.n_outputs().to_string()}
                }),
            ),
        ),
        (
            "indexer-api/schema-v1.json",
            fixture_base!(
                "fx-p00-indexer-schema-v1",
                "sdk-libs/client/src/rpc.rs",
                "Context; MerkleProof; NonInclusionProof",
                "sdk-libs/client/tests/test_indexer.rs",
                "P00",
                "indexer logical schema values and path bounds",
                json!({"blockTime":context.block_time.to_string()}),
                json!({
                    "merkle":{"leafIndex":merkle.leaf_index.to_string(),"pathLength":merkle.path.len().to_string(),"rootIndex":merkle.root_index.to_string()},
                    "nonInclusion":{"highIndex":non_inclusion.high_element_index.to_string(),"lowIndex":non_inclusion.low_element_index.to_string(),"pathLength":non_inclusion.path.len().to_string()}
                }),
            ),
        ),
        (
            "api/prover-request-v1.json",
            fixture_base!(
                "fx-p00-api-prover-request-v1",
                "sdk-libs/client/src/prover/inputs.rs",
                "TransferInput::new_dummy",
                "sdk-libs/client/tests/prover.rs",
                "P00",
                "prover request JSON field spelling and deterministic values",
                json!({"dummyBlinding":hex(&[8;31]),"testOnlySecret":true}),
                json!({"request":prover_request,"resultError":prover_result_error}),
            ),
        ),
        (
            "client/proof-result-compression-v1.json",
            fixture_base!(
                "fx-p00-client-proof-compression-v1",
                "sdk-libs/client/src/prover/proof.rs",
                "ProofCompressed::to_p256_proof",
                "sdk-libs/client/tests/transaction_proving.rs",
                "P00",
                "prover result conversion, commitment fields, and wrong-rail error",
                json!({"compressed":true}),
                json!({
                    "aBytes":hex(&p256.a),
                    "bBytes":hex(&p256.b),
                    "cBytes":hex(&p256.c),
                    "commitmentBytes":hex(&p256.commitment),
                    "commitmentPokBytes":hex(&p256.commitment_pok),
                    "error":error_json(&missing_commitment_error)
                }),
            ),
        ),
        (
            "wallet/asset-sequence-v1.json",
            fixture_base!(
                "fx-p00-wallet-sequence-v1",
                "sdk-libs/transaction/src/wallet/asset.rs",
                "AssetRegistry",
                "sdk-libs/wallet/tests/transaction.rs",
                "P00",
                "pure wallet asset state sequence and error evidence",
                json!({"insertAssetId":"2","mintBytes":hex(mint.as_array())}),
                json!({"resolvedMintBytes":hex(registry.resolve(2)?.as_array()),"reservedError":error_json(&reserved_error)}),
            ),
        ),
        (
            "merkle-tree/paths-v1.json",
            fixture_base!(
                "fx-p00-merkle-paths-v1",
                "sdk-libs/merkle-tree/src/lib.rs; sdk-libs/merkle-tree/src/indexed.rs; program-libs/hasher/src",
                "MerkleTree; IndexedMerkleTree; Poseidon; Sha256; Keccak",
                "sdk-libs/program-test/src/indexer.rs",
                "P00",
                "exact production hasher, Merkle path, indexed ordering, and non-inclusion proof bytes",
                json!({
                    "canopyDepth":"1",
                    "dummyBlindingBytes":hex(&[8;31]),
                    "height":"4",
                    "indexedInsertions":["30","10","20"],
                    "leafBytePatterns":["01","02","03","04"],
                    "nonInclusionQueries":["5","15","25","35"],
                    "nullifierRootBytes":hex(&[10;32]),
                    "stateRootBytes":hex(&[9;32]),
                    "testOnlySecret":true
                }),
                json!({
                    "dummyNullifierBytes":hex(&dummy_nullifier),
                    "hashers":merkle_vectors["hashers"],
                    "indexerEmptyRootBytes":hex(&indexer_root),
                    "indexed":merkle_vectors["indexed"],
                    "nonInclusionPathLength":dummy.nullifier_low_path_elements.len().to_string(),
                    "statePathLength":dummy.state_path_elements.len().to_string(),
                    "vectorCounts":{
                        "hasherVectors":"3",
                        "inclusionProofs":"12",
                        "indexedVectors":"3",
                        "nonInclusionProofs":"12"
                    }
                }),
            ),
        ),
        (
            "smart-account-client/standard-create-v1.json",
            fixture_base!(
                "fx-p00-smart-account-create-v1",
                "program-tests/test-utils/src/smart_account.rs",
                "StandardAccounts::create_ixs",
                "sdk-libs/smart-account-client/src/lib.rs",
                "P00",
                "smart-account production builder bytes and account flags",
                json!({"creator":creator.to_string()}),
                json!({"instructions":smart_ixs.iter().map(instruction_json).collect::<Vec<_>>()}),
            ),
        ),
        (
            "test-kit/standard-accounts-v1.json",
            fixture_base!(
                "fx-p00-test-kit-standard-accounts-v1",
                "program-tests/test-utils/src/smart_account.rs",
                "standard_accounts",
                "program-tests smart-account support",
                "P00",
                "deterministic test support account addresses",
                json!({}),
                json!({
                    "foresterVault":accounts.forester_vault.to_string(),
                    "mergeVault":accounts.merge_vault.to_string(),
                    "protocolVault":accounts.protocol_vault.to_string(),
                    "treeVault":accounts.tree_vault.to_string(),
                    "zoneVault":accounts.zone_vault.to_string()
                }),
            ),
        ),
        (
            "workflows/deposit-v1.json",
            fixture_base!(
                "fx-workflow-instruction-deposit-v1",
                "program-libs/interface/src/instruction/builders/deposit.rs",
                "Deposit::instruction",
                "program-tests/shielded-pool/tests/localnet_deposit.rs",
                "P00",
                "initial instruction workflow oracle",
                json!({
                    "amount":"42",
                    "blindingBytes":hex(&[5;31]),
                    "memoBytes":hex(b"fixture"),
                    "ownerBytes":hex(&[4;32]),
                    "rail":"SOL",
                    "testOnlySecret":true,
                    "viewTagBytes":hex(&[3;32])
                }),
                json!({"depositTag":tag::DEPOSIT.to_string(),"instruction":deposit_expected}),
            ),
        ),
        (
            "client/proof-input-v1.json",
            fixture_base!(
                "fx-p00-client-proof-input-v1",
                "sdk-libs/client/src/prover/inputs.rs",
                "TransferInput::new_dummy",
                "sdk-libs/client/tests/steps/mod.rs",
                "P00",
                "proof input field and path evidence",
                json!({
                    "dummyBlindingBytes":hex(&[8;31]),
                    "ownerHashBytes":hex(&[11;32]),
                    "testOnlySecret":true
                }),
                json!({
                    "isDummy":dummy.is_dummy.to_string(),
                    "nullifierBytes":hex(&dummy_nullifier),
                    "nullifierTreeRoot":dummy.nullifier_tree_root.to_string(),
                    "utxoTreeRoot":dummy.utxo_tree_root.to_string()
                }),
            ),
        ),
    ];
    let merkle_fixture = fixtures
        .iter_mut()
        .find(|(path, _)| *path == "merkle-tree/paths-v1.json")
        .map(|(_, fixture)| fixture)
        .ok_or_else(|| anyhow::anyhow!("Merkle fixture is missing"))?;
    merkle_fixture["sourceRevision"] = Value::String(MERKLE_SHA.to_string());
    fixtures.extend(keypair_fixtures(&keypair_vectors)?);
    fixtures.extend(transaction_fixtures(&transaction_vectors)?);
    fixtures.push(api_fixture(&api_vectors, baseline)?);
    let (client_fixtures, client_revision) = stamp_current_client(
        client_fixtures(root, &client_vectors)?,
        &current_client_revision(root)?,
        &root.join("sdk-libs/ts/fixtures"),
    )?;
    fixtures.extend(client_fixtures);
    fixtures.extend(instruction_workflow_fixtures(&client_vectors)?);
    fixtures.extend(wallet_fixtures(&wallet_vectors)?);
    fixtures.extend(workflow_fixtures(&wallet_vectors)?);
    for (path, fixture) in &mut fixtures {
        attach_proof_verifying_keys(root, path, fixture)?;
    }
    Ok((fixtures, client_revision))
}

/// Proof fixtures record the verifying-key modules the release verifier loads
/// for the rail each fixture exercises. SHA-256 is over the committed
/// `program-libs/interface/src/verifying_keys/<module>.rs` source.
fn attach_proof_verifying_keys(root: &Path, path: &str, fixture: &mut Value) -> Result<()> {
    let modules: &[(&str, &str)] = match path {
        "client/proof-validity-v1.json" => &[
            ("eddsa", "transfer_confidential_1_1"),
            ("p256", "transfer_p256_confidential_1_1"),
        ],
        "client/proof-result-compression-v1.json" => &[("p256", "transfer_p256_confidential_1_1")],
        "client/proof-input-v1.json" => &[("eddsa", "transfer_confidential_1_1")],
        _ => return Ok(()),
    };
    let mut keys = Vec::with_capacity(modules.len());
    for (rail, module) in modules {
        let bytes = fs::read(
            root.join("program-libs/interface/src/verifying_keys")
                .join(format!("{module}.rs")),
        )
        .with_context(|| format!("read verifying key module {module}"))?;
        keys.push(json!({
            "module": module,
            "rail": rail,
            "sha256": sha256(&bytes),
        }));
    }
    fixture["verifyingKeys"] = Value::Array(keys);
    Ok(())
}

fn instruction_json(instruction: &solana_instruction::Instruction) -> Value {
    json!({
        "accounts": instruction.accounts.iter().map(|account| json!({
            "address": account.pubkey.to_string(),
            "signer": account.is_signer,
            "writable": account.is_writable
        })).collect::<Vec<_>>(),
        "dataBytes": hex(&instruction.data),
        "programId": instruction.program_id.to_string()
    })
}

fn capture_prover_request(inputs: &TransferInputs) -> Result<(Value, Value)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || -> Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                bail!("prover request ended before headers");
            }
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec())?;
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>())
            })
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("prover request lacks content-length"))?;
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                bail!("prover request body was truncated");
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        sender.send(bytes[header_end..header_end + content_length].to_vec())?;
        stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )?;
        Ok(())
    });
    let client = ProverClient::new(format!("http://{address}"));
    let result_error = client
        .prove_transfer(inputs)
        .expect_err("empty prover result must be rejected");
    let request: Value = serde_json::from_slice(&receiver.recv()?)?;
    server
        .join()
        .map_err(|_| anyhow::anyhow!("fixture prover server panicked"))??;
    Ok((request, error_json(&result_error)))
}

fn production_merkle_vectors(root: &Path) -> Result<Value> {
    let build = Command::new("rustup")
        .current_dir(root)
        .args([
            "run",
            "1.97.0",
            "cargo",
            "build",
            "-p",
            "zolana-merkle-tree",
            "-p",
            "zolana-hasher",
            "-p",
            "num-bigint",
        ])
        .output()
        .context("build production Merkle crates")?;
    if !build.status.success() {
        bail!(
            "build production Merkle crates: {}",
            String::from_utf8_lossy(&build.stderr)
        );
    }

    let metadata: Value = serde_json::from_str(&command_text(
        root,
        "rustup",
        &[
            "run",
            "1.97.0",
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
        ],
    )?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cargo metadata lacks target_directory"))?,
    );
    let deps = target.join("debug/deps");
    let binary = target.join("ts-fixtures-merkle");
    let extern_arg = |name: &str, path: PathBuf| format!("{name}={}", path.display());
    let compile = Command::new("rustup")
        .current_dir(root)
        .args([
            "run",
            "1.97.0",
            "rustc",
            "--edition=2021",
            "xtask/src/ts_fixtures_merkle.rs",
            "-L",
        ])
        .arg(format!("dependency={}", deps.display()))
        .args(["--extern"])
        .arg(extern_arg(
            "zolana_merkle_tree",
            target.join("debug/libzolana_merkle_tree.rlib"),
        ))
        .args(["--extern"])
        .arg(extern_arg(
            "zolana_hasher",
            target.join("debug/libzolana_hasher.rlib"),
        ))
        .args(["--extern"])
        .arg(extern_arg(
            "num_bigint",
            target.join("debug/libnum_bigint.rlib"),
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .context("compile production Merkle fixture oracle")?;
    if !compile.status.success() {
        bail!(
            "compile production Merkle fixture oracle: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
    }

    let output = Command::new(&binary)
        .output()
        .context("run production Merkle fixture oracle")?;
    if !output.status.success() {
        bail!(
            "run production Merkle fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let start = output
        .stdout
        .iter()
        .position(|byte| *byte == b'{')
        .ok_or_else(|| anyhow::anyhow!("Merkle fixture oracle produced no JSON"))?;
    let vectors: Value = serde_json::from_slice(&output.stdout[start..])?;
    verify_merkle_vectors(&vectors)?;
    Ok(vectors)
}

fn verify_merkle_vectors(vectors: &Value) -> Result<()> {
    let hashers = vectors["hashers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Merkle hashers are not an array"))?;
    let indexed = vectors["indexed"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("indexed Merkle vectors are not an array"))?;
    if hashers.len() != 3 || indexed.len() != 3 {
        bail!("Merkle oracle must emit three hasher and indexed vectors");
    }
    let mut ids = BTreeSet::new();
    for vector in hashers {
        register_vector_id(vector, &mut ids)?;
        let proofs = vector["proofs"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Merkle proofs are not an array"))?;
        if proofs.len() != 4 || proofs.iter().any(|proof| proof["verified"] != true) {
            bail!("each hasher must emit four verified inclusion proofs");
        }
        for proof in proofs {
            register_vector_id(proof, &mut ids)?;
        }
    }
    for vector in indexed {
        register_vector_id(vector, &mut ids)?;
        let proofs = vector["nonInclusionProofs"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("non-inclusion proofs are not an array"))?;
        if proofs.len() != 4 || proofs.iter().any(|proof| proof["verified"] != true) {
            bail!("each hasher must emit four verified non-inclusion proofs");
        }
        for proof in proofs {
            register_vector_id(proof, &mut ids)?;
        }
    }
    if ids.len() != 30 {
        bail!(
            "Merkle oracle emitted {} unique vector IDs, expected 30",
            ids.len()
        );
    }
    Ok(())
}

fn register_vector_id(vector: &Value, ids: &mut BTreeSet<String>) -> Result<()> {
    let id = vector["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Merkle vector lacks an ID"))?;
    if !ids.insert(id.to_string()) {
        bail!("duplicate Merkle vector ID {id}");
    }
    Ok(())
}

fn production_keypair_vectors(root: &Path) -> Result<Value> {
    let artifacts = cargo_rlibs(root, &["build", "-p", "zolana-keypair", "-p", "zolana-api"])?;
    let metadata: Value = serde_json::from_str(&command_text(
        root,
        "rustup",
        &[
            "run",
            "1.97.0",
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
        ],
    )?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cargo metadata lacks target_directory"))?,
    );
    let mut externs = [
        ("aes", "aes@0.8.4"),
        ("ctr", "ctr@0.9.2"),
        ("ed25519_dalek", "ed25519-dalek@2.2.0"),
        ("hkdf", "hkdf@0.12.4"),
        ("p256", "p256@0.13.2"),
        ("rand", "rand@0.8.7"),
        ("sha2", "sha2@0.10.9"),
        ("solana_address", "solana-address@2.6.1"),
        ("solana_keypair", "solana-keypair@3.1.2"),
        ("thiserror", "thiserror@2.0.18"),
        ("zeroize", "zeroize@1.9.0"),
        ("zolana_hasher", "zolana-hasher@5.0.0"),
    ]
    .into_iter()
    .map(|(name, package)| Ok((name, rlib(&artifacts, name, package)?)))
    .collect::<Result<Vec<_>>>()?;
    externs.push((
        "serde_json",
        rlib(&artifacts, "serde_json", "serde_json@1.0.150")?,
    ));

    let binary = target.join("ts-fixtures-keypair");
    let mut compile = Command::new("rustup");
    compile
        .current_dir(root)
        .args([
            "run",
            "1.97.0",
            "rustc",
            "--edition=2021",
            "xtask/src/ts_fixtures_keypair.rs",
            "-L",
        ])
        .arg(format!(
            "dependency={}",
            target.join("debug/deps").display()
        ));
    for (name, path) in externs {
        compile
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = compile
        .arg("-o")
        .arg(&binary)
        .output()
        .context("compile production keypair fixture oracle")?;
    if !output.status.success() {
        bail!(
            "compile production keypair fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new(&binary)
        .output()
        .context("run production keypair fixture oracle")?;
    if !output.status.success() {
        bail!(
            "run production keypair fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let vectors: Value = serde_json::from_slice(&output.stdout)?;
    verify_keypair_vectors(&vectors)?;
    Ok(vectors)
}

fn cargo_rlibs(root: &Path, args: &[&str]) -> Result<Vec<(String, String, PathBuf)>> {
    let output = Command::new("rustup")
        .current_dir(root)
        .args(["run", "1.97.0", "cargo"])
        .args(args)
        .arg("--message-format=json")
        .output()
        .with_context(|| format!("cargo {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "cargo {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut artifacts = Vec::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        let Ok(message) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(name) = message["target"]["name"].as_str() else {
            continue;
        };
        let Some(package) = message["package_id"].as_str() else {
            continue;
        };
        let Some(files) = message["filenames"].as_array() else {
            continue;
        };
        for file in files {
            let Some(file) = file.as_str() else {
                continue;
            };
            if file.ends_with(".rlib") {
                artifacts.push((name.to_string(), package.to_string(), PathBuf::from(file)));
            }
        }
    }
    Ok(artifacts)
}

fn rlib(artifacts: &[(String, String, PathBuf)], name: &str, package: &str) -> Result<PathBuf> {
    let mut matches = artifacts
        .iter()
        .filter(|(target, id, _)| target == name && id.contains(package))
        .map(|(_, _, path)| path.clone())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    match matches.first() {
        Some(path) => Ok(path.clone()),
        None => bail!("no {name} artifact for {package}"),
    }
}

fn verify_keypair_vectors(vectors: &Value) -> Result<()> {
    let sections = [
        "constants",
        "encryption",
        "error",
        "hash",
        "lib",
        "merge",
        "nullifier_key",
        "pubkey",
        "shielded",
        "signing_key",
        "tests",
        "viewing_key",
    ];
    let object = vectors
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("keypair oracle is not an object"))?;
    if object.len() != sections.len() {
        bail!(
            "keypair oracle emitted {} sections, expected {}",
            object.len(),
            sections.len()
        );
    }
    for section in sections {
        if vectors[section]["inputs"]["testOnlySecret"] != true {
            bail!("{section} fixture does not mark test secrets");
        }
    }
    let tests = &vectors["tests"]["expected"];
    for check in [
        "allTagDirectionsAgree",
        "ed25519RoundTripVerified",
        "mergeRoundTripVerified",
        "p256RoundTripVerified",
        "slotRoundTripVerified",
    ] {
        if tests[check] != true {
            bail!("keypair oracle self-check failed: {check}");
        }
    }
    Ok(())
}

fn keypair_fixtures(vectors: &Value) -> Result<Vec<(&'static str, Value)>> {
    let domains = [
        (
            "constants",
            "keypair/constants.json",
            "fx-p00-keypair-constants-v1",
            "sdk-libs/keypair/src/constants.rs",
            "PUBLIC_KEY_LEN; P256_PUBKEY_LEN; BLINDING_LEN; SALT_LEN; VIEW_TAG_LEN; P_CONST_SEC1",
            "sdk-libs/keypair/src/constants.rs",
            "public lengths, domain bytes, and recorded randomness boundaries",
        ),
        (
            "encryption",
            "keypair/encryption.json",
            "fx-p00-keypair-encryption-v1",
            "sdk-libs/keypair/src/encryption.rs",
            "ViewingKey::encrypt_slot; decrypt_utxo; decrypt_slot_ephemeral",
            "sdk-libs/keypair/src/encryption.rs",
            "ECDH, HKDF, AES slot bytes, both decrypt paths, and slot separation",
        ),
        (
            "error",
            "keypair/error.json",
            "fx-p00-keypair-error-v1",
            "sdk-libs/keypair/src/error.rs",
            "KeypairError",
            "sdk-libs/keypair/src/error.rs",
            "malformed key, rail, padding, and tampered-signature evidence",
        ),
        (
            "hash",
            "keypair/hash.json",
            "fx-p00-keypair-hash-v1",
            "sdk-libs/keypair/src/hash.rs",
            "sha256; sha256_be; split_be_128; PublicKey::hash; owner_pk_field",
            "sdk-libs/keypair/src/hash.rs",
            "hash, field split, public hash, and owner field bytes",
        ),
        (
            "lib",
            "keypair/lib.json",
            "fx-p00-keypair-lib-v1",
            "sdk-libs/keypair/src/lib.rs",
            "Signature; ECDSASignature; random_blinding; random_salt",
            "sdk-libs/keypair/src/lib.rs",
            "root aliases, rail variants, and explicit recorded randomness",
        ),
        (
            "merge",
            "keypair/merge.json",
            "fx-p00-keypair-merge-v1",
            "sdk-libs/keypair/src/merge.rs",
            "encrypt_verifiable; decrypt_verifiable; merge_public_contribution; merge_ciphertext_hash",
            "sdk-libs/keypair/src/merge.rs",
            "merge ciphertext, ephemeral public key, public contribution, and hashes",
        ),
        (
            "nullifier_key",
            "keypair/nullifier_key.json",
            "fx-p00-keypair-nullifier-key-v1",
            "sdk-libs/keypair/src/nullifier_key.rs",
            "NullifierKey::from_signing_key; pubkey; nullifier",
            "sdk-libs/keypair/src/nullifier_key.rs",
            "nullifier secret derivation, public key, and UTXO nullifier bytes",
        ),
        (
            "pubkey",
            "keypair/pubkey.json",
            "fx-p00-keypair-pubkey-v1",
            "sdk-libs/keypair/src/pubkey.rs",
            "P256Pubkey; PublicKey",
            "sdk-libs/keypair/src/pubkey.rs",
            "P256 and Ed25519 tagged parsing, fields, and round trips",
        ),
        (
            "shielded",
            "keypair/shielded.json",
            "fx-p00-keypair-shielded-v1",
            "sdk-libs/keypair/src/shielded.rs",
            "ShieldedKeypair; ShieldedAddress; CompressedShieldedAddress",
            "sdk-libs/keypair/src/shielded.rs",
            "both ownership rails, address fields, owner hashes, and compression",
        ),
        (
            "signing_key",
            "keypair/signing_key.json",
            "fx-p00-keypair-signing-key-v1",
            "sdk-libs/keypair/src/signing_key.rs",
            "SigningKey::from_bytes; from_ed25519; pubkey; sign; verify",
            "sdk-libs/keypair/src/signing_key.rs",
            "fixed P256 and Ed25519 parse, public derivation, signature, and verification",
        ),
        (
            "tests",
            "keypair/tests.json",
            "fx-p00-keypair-tests-v1",
            "sdk-libs/keypair/tests",
            "production keypair feature and step scenarios",
            "sdk-libs/keypair/tests/bdd.rs",
            "self-verified cross-domain production behavior",
        ),
        (
            "viewing_key",
            "keypair/viewing_key.json",
            "fx-p00-keypair-viewing-key-v1",
            "sdk-libs/keypair/src/viewing_key.rs",
            "ViewingKey",
            "sdk-libs/keypair/src/viewing_key.rs",
            "public key, ECDH, purpose roots, all tag directions, seed, and transaction key",
        ),
    ];
    domains
        .into_iter()
        .map(
            |(section, path, id, rust_path, symbol, inventory_row, responsibility)| {
                let value = &vectors[section];
                if !value.is_object() {
                    bail!("keypair oracle lacks {section}");
                }
                Ok((
                    path,
                    fixture_base!(
                        id,
                        rust_path,
                        symbol,
                        inventory_row,
                        "P00",
                        responsibility,
                        value["inputs"].clone(),
                        value["expected"].clone(),
                    ),
                ))
            },
        )
        .collect()
}

fn production_transaction_vectors(root: &Path) -> Result<Value> {
    let artifacts = cargo_rlibs(
        root,
        &[
            "build",
            "-p",
            "zolana-transaction",
            "-p",
            "zolana-api",
            "--features",
            "zolana-transaction/parallel",
        ],
    )?;
    let metadata: Value = serde_json::from_str(&command_text(
        root,
        "rustup",
        &[
            "run",
            "1.97.0",
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
        ],
    )?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cargo metadata lacks target_directory"))?,
    );
    let externs = [
        ("p256", "p256@0.13.2"),
        ("serde_json", "serde_json@1.0.150"),
        ("wincode", "wincode@0.5.5"),
        ("zolana_interface", "zolana-interface@0.1.0"),
        ("zolana_keypair", "zolana-keypair@0.1.0"),
        ("zolana_transaction", "zolana-transaction@0.1.0"),
    ]
    .into_iter()
    .map(|(name, package)| Ok((name, rlib(&artifacts, name, package)?)))
    .collect::<Result<Vec<_>>>()?;

    let binary = target.join("ts-fixtures-transaction");
    let mut compile = Command::new("rustup");
    compile
        .current_dir(root)
        .args([
            "run",
            "1.97.0",
            "rustc",
            "--edition=2021",
            "xtask/src/ts_fixtures_transaction.rs",
            "-L",
        ])
        .arg(format!(
            "dependency={}",
            target.join("debug/deps").display()
        ));
    for (name, path) in externs {
        compile
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = compile
        .arg("-o")
        .arg(&binary)
        .output()
        .context("compile production transaction fixture oracle")?;
    if !output.status.success() {
        bail!(
            "compile production transaction fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let output = Command::new(&binary)
        .output()
        .context("run production transaction fixture oracle")?;
    if !output.status.success() {
        bail!(
            "run production transaction fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let vectors: Value = serde_json::from_slice(&output.stdout)?;
    verify_transaction_vectors(&vectors)?;
    Ok(vectors)
}

fn verify_transaction_vectors(vectors: &Value) -> Result<()> {
    let sections = [
        "asset",
        "authority",
        "data",
        "merge",
        "serialization",
        "split",
        "tests",
        "transact",
        "transfer",
        "utxo",
        "wallet_state",
        "wallet_sync",
        "zone",
    ];
    let object = vectors
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("transaction oracle is not an object"))?;
    if object.len() != sections.len() {
        bail!(
            "transaction oracle emitted {} sections, expected {}",
            object.len(),
            sections.len()
        );
    }
    for section in sections {
        if vectors[section]["inputs"]["testOnlySecret"] != true {
            bail!("{section} transaction fixture does not mark test secrets");
        }
    }
    for (section, check) in [
        ("data", "roundTripVerified"),
        ("wallet_sync", "parallelEquivalent"),
    ] {
        if section == "data" && vectors[section]["expected"][check] != true {
            bail!("transaction oracle self-check failed: {section}.{check}");
        }
        if section == "wallet_sync"
            && (vectors[section]["expected"][check]["utxosEqual"] != true
                || vectors[section]["expected"][check]["historyEqual"] != true)
        {
            bail!("transaction oracle self-check failed: {section}.{check}");
        }
    }
    let families = vectors["serialization"]["expected"]["families"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("transaction serialization families are not an object"))?;
    if families.len() != 9 {
        bail!(
            "transaction oracle emitted {} serialization families, expected 9",
            families.len()
        );
    }
    Ok(())
}

fn transaction_fixtures(vectors: &Value) -> Result<Vec<(&'static str, Value)>> {
    let domains = [
        (
            "data",
            "transaction/data-v1.json",
            "fx-p00-transaction-data-v1",
            "sdk-libs/transaction/src/data.rs",
            "DataRecord; Data",
            "sdk-libs/transaction/src/data.rs",
            "record order, accessors, u16 lengths, round trips, and malformed data",
        ),
        (
            "utxo",
            "transaction/utxo-v1.json",
            "fx-p00-transaction-utxo-v1",
            "sdk-libs/transaction/src/utxo.rs; sdk-libs/transaction/src/instructions/types.rs",
            "Utxo; ProofInputUtxo; SppProofInputUtxo; derive_blinding; owner_utxo_hash",
            "sdk-libs/transaction/src/utxo.rs",
            "UTXO fields, proof fields, hashes, nullifiers, blindings, dummies, and errors",
        ),
        (
            "serialization",
            "transaction/serialization-v1.json",
            "fx-p00-transaction-serialization-v1",
            "sdk-libs/transaction/src/serialization",
            "all UtxoSerialization families and EncryptedScheme",
            "sdk-libs/transaction/tests/features/serialization.feature",
            "exact wincode, Borsh, fixed layouts, length prefixes, round trips, and malformed bytes",
        ),
        (
            "transact",
            "transaction/transact-v1.json",
            "fx-p00-transaction-transact-v1",
            "sdk-libs/transaction/src/instructions/transact",
            "Shape; ExternalData; SppProofInputs; PrivateTxHash; InputUtxo",
            "sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs",
            "shape selection, external hashes, proof inputs, signed fields, wire mapping, and P256 proof widths",
        ),
        (
            "transfer",
            "transaction/transfer-v1.json",
            "fx-p00-transaction-transfer-v1",
            "sdk-libs/transaction/src/instructions/transact/transfer.rs",
            "ConfidentialTransfer; PreparedTransfer; WithdrawalTarget",
            "sdk-libs/transaction/tests/features/transfer.feature",
            "transfer change and recipient slots, conservation, hashes, shapes, and errors",
        ),
        (
            "split",
            "transaction/split-v1.json",
            "fx-p00-transaction-split-v1",
            "sdk-libs/transaction/src/instructions/transact/split.rs",
            "ConfidentialSplit; PreparedSplit",
            "sdk-libs/transaction/tests/features/split.feature",
            "split bundle bytes, conservation, owner-bound padding, blindings, and errors",
        ),
        (
            "merge",
            "transaction/merge-v1.json",
            "fx-p00-transaction-merge-v1",
            "sdk-libs/transaction/src/instructions/merge.rs",
            "Merge; PreparedMerge; MERGE_INPUTS",
            "sdk-libs/transaction/src/instructions/merge.rs",
            "merge contexts, deterministic padding inputs, output hash, and validation errors",
        ),
        (
            "zone",
            "transaction/zone-v1.json",
            "fx-p00-transaction-zone-v1",
            "sdk-libs/transaction/src/instructions/merge_zone.rs; sdk-libs/transaction/src/instructions/zone_authority.rs",
            "MergeZone; PreparedMergeZone; zone authority inputs",
            "sdk-libs/transaction/src/instructions/merge_zone.rs",
            "zone-bound input and output hashes, contexts, deterministic padding, and errors",
        ),
        (
            "asset",
            "transaction/asset-v1.json",
            "fx-p00-transaction-asset-v1",
            "sdk-libs/transaction/src/wallet/asset.rs",
            "SOL_ASSET_ID; SOL_MINT; AssetRegistry",
            "sdk-libs/transaction/tests/features/asset.feature",
            "reserved SOL mapping, insertion, both lookups, field lookup, and conflicts",
        ),
        (
            "authority",
            "transaction/authority-v1.json",
            "fx-p00-transaction-authority-v1",
            "sdk-libs/transaction/src/wallet/authority.rs",
            "WalletAuthority; SyncWalletAuthority; LocalWalletAuthority; envelopes",
            "sdk-libs/transaction/src/wallet/authority.rs",
            "authority material, approval input, deterministic P256 signature, and envelope fields",
        ),
        (
            "wallet_state",
            "transaction/wallet-state-v1.json",
            "fx-p00-transaction-wallet-state-v1",
            "sdk-libs/transaction/src/wallet/state.rs",
            "Wallet; WalletUtxo; balances; history",
            "sdk-libs/transaction/tests/wallet_history.rs",
            "wallet UTXOs, spent state, filtered balances, compact balances, and history ordering",
        ),
        (
            "wallet_sync",
            "transaction/wallet-sync-v1.json",
            "fx-p00-transaction-wallet-sync-v1",
            "sdk-libs/transaction/src/wallet/sync.rs; sdk-libs/transaction/src/wallet/parallel.rs",
            "Wallet::sync; sync_parallel; decrypt_transactions",
            "sdk-libs/transaction/tests/wallet_prop.rs",
            "incremental and idempotent sync, worker equivalence, tamper rejection, and authority errors",
        ),
        (
            "tests",
            "transaction/frozen-tests-v1.json",
            "fx-p00-transaction-frozen-tests-v1",
            "sdk-libs/transaction/tests",
            "assigned frozen transaction scenarios and persisted regression seeds",
            "sdk-libs/transaction/tests/wallet_prop.proptest-regressions",
            "assigned scenario domains and exact persisted property regression seeds",
        ),
    ];
    domains
        .into_iter()
        .map(
            |(section, path, id, rust_path, symbol, inventory_row, responsibility)| {
                let value = &vectors[section];
                if !value.is_object() {
                    bail!("transaction oracle lacks {section}");
                }
                Ok((
                    path,
                    fixture_base!(
                        id,
                        rust_path,
                        symbol,
                        inventory_row,
                        "P00",
                        responsibility,
                        value["inputs"].clone(),
                        value["expected"].clone(),
                    ),
                ))
            },
        )
        .collect()
}

fn production_api_vectors(root: &Path) -> Result<Value> {
    let artifacts = cargo_rlibs(root, &["build", "-p", "zolana-api"])?;
    let metadata: Value = serde_json::from_str(&command_text(
        root,
        "rustup",
        &[
            "run",
            "1.97.0",
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
        ],
    )?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cargo metadata lacks target_directory"))?,
    );
    let externs = [
        ("serde_json", "serde_json@1.0.150"),
        ("zolana_api", "zolana-api#0.1.0"),
    ]
    .into_iter()
    .map(|(name, package)| Ok((name, rlib(&artifacts, name, package)?)))
    .collect::<Result<Vec<_>>>()?;

    let binary = target.join("ts-fixtures-api");
    let mut compile = Command::new("rustup");
    compile
        .current_dir(root)
        .args([
            "run",
            "1.97.0",
            "rustc",
            "--edition=2021",
            "xtask/src/ts_fixtures_api.rs",
            "-L",
        ])
        .arg(format!(
            "dependency={}",
            target.join("debug/deps").display()
        ));
    for (name, path) in externs {
        compile
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = compile
        .arg("-o")
        .arg(&binary)
        .output()
        .context("compile production API fixture oracle")?;
    if !output.status.success() {
        bail!(
            "compile production API fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = Command::new(&binary)
        .output()
        .context("run production API fixture oracle")?;
    if !output.status.success() {
        bail!(
            "run production API fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let vectors: Value = serde_json::from_slice(&output.stdout)?;
    verify_api_vectors(&vectors)?;
    Ok(vectors)
}

fn verify_api_vectors(vectors: &Value) -> Result<()> {
    let successes = vectors["expected"]["successes"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("API oracle successes is not an array"))?;
    if successes.len() != 6 {
        bail!(
            "API oracle emitted {} success cases, expected 6",
            successes.len()
        );
    }
    let methods = successes
        .iter()
        .filter_map(|case| case["request"]["body"]["method"].as_str())
        .collect::<BTreeSet<_>>();
    if methods.len() != 5 {
        bail!("API oracle must cover all five methods");
    }
    for name in [
        "http",
        "invalidOptionalLimit",
        "invalidRequiredLimit",
        "jsonRpc",
        "missingResult",
    ] {
        if !vectors["expected"]["errors"][name].is_object() {
            bail!("API oracle lacks {name} error");
        }
    }
    Ok(())
}

fn api_fixture(vectors: &Value, baseline: &str) -> Result<(&'static str, Value)> {
    if !vectors["inputs"].is_object() || !vectors["expected"].is_object() {
        bail!("API oracle lacks inputs or expected values");
    }
    let mut fixture = fixture_base!(
        "fx-p00-api-transport-v1",
        "sdk-libs/zolana-api/src/lib.rs; sdk-libs/indexer-api/src/lib.rs",
        "BlockingZolanaApi::{get_encrypted_utxos_by_tags,get_shielded_transactions_by_tags,get_merkle_proofs,get_non_inclusion_proofs,get_nullifier_queue_elements}; ApiError",
        "sdk-libs/zolana-api/src/lib.rs",
        "P00",
        "production HTTP requests, decoded responses, defaults, limits, and shared transport errors",
        vectors["inputs"].clone(),
        vectors["expected"].clone(),
    );
    fixture["sourceRevision"] = Value::String(baseline.to_string());
    Ok(("api/transport-v1.json", fixture))
}

fn production_client_vectors(root: &Path) -> Result<Value> {
    let artifacts = cargo_rlibs(
        root,
        &[
            "build",
            "-p",
            "zolana-client",
            "-p",
            "zolana-program-test",
            "--features",
            "zolana-client/solana-rpc",
        ],
    )?;
    let metadata: Value = serde_json::from_str(&command_text(
        root,
        "rustup",
        &[
            "run",
            "1.97.0",
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
        ],
    )?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cargo metadata lacks target_directory"))?,
    );
    let externs = [
        ("ark_bn254", "ark-bn254@0.5.0"),
        ("ark_ec", "ark-ec@0.5.0"),
        ("ark_ff", "ark-ff@0.5.0"),
        ("bincode", "bincode@1.3.3"),
        ("serde_json", "serde_json@1.0.150"),
        (
            "solana_compute_budget_interface",
            "solana-compute-budget-interface@3.0.0",
        ),
        ("solana_address", "solana-address@2.6.1"),
        ("solana_hash", "solana-hash@4.5.0"),
        ("solana_instruction", "solana-instruction@3.4.0"),
        ("solana_message", "solana-message@3.1.0"),
        ("solana_pubkey", "solana-pubkey@4.2.0"),
        ("zolana_client", "zolana-client@0.1.0"),
        ("zolana_event", "zolana-event@0.1.0"),
        ("zolana_hasher", "zolana-hasher@5.0.0"),
        ("zolana_interface", "zolana-interface@0.1.0"),
        ("zolana_keypair", "zolana-keypair@0.1.0"),
        ("zolana_program_test", "zolana-program-test@0.23.0"),
        ("zolana_transaction", "zolana-transaction@0.1.0"),
    ]
    .into_iter()
    .map(|(name, package)| Ok((name, rlib(&artifacts, name, package)?)))
    .collect::<Result<Vec<_>>>()?;

    let binary = target.join("ts-fixtures-client");
    let mut compile = Command::new("rustup");
    compile
        .current_dir(root)
        .args([
            "run",
            "1.97.0",
            "rustc",
            "--edition=2021",
            "xtask/src/ts_fixtures_client.rs",
            "-L",
        ])
        .arg(format!(
            "dependency={}",
            target.join("debug/deps").display()
        ));
    for (name, path) in externs {
        compile
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = compile
        .arg("-o")
        .arg(&binary)
        .output()
        .context("compile production client fixture oracle")?;
    if !output.status.success() {
        bail!(
            "compile production client fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = Command::new(&binary)
        .output()
        .context("run production client fixture oracle")?;
    if !output.status.success() {
        bail!(
            "run production client fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let vectors: Value = serde_json::from_slice(&output.stdout)?;
    verify_client_vectors(&vectors)?;
    Ok(vectors)
}

fn verify_client_vectors(vectors: &Value) -> Result<()> {
    for section in [
        "errors",
        "prover",
        "proof",
        "rpc",
        "workflow_transfer",
        "workflow_withdraw_sol",
        "workflow_withdraw_spl",
    ] {
        if !vectors[section].is_object() {
            bail!("client oracle lacks {section}");
        }
    }
    if vectors["prover"]["expected"]["rails"]
        .as_array()
        .is_none_or(|rails| {
            rails.len() != 2
                || rails.iter().any(|rail| {
                    rail["shapes"]
                        .as_array()
                        .is_none_or(|shapes| shapes.len() != 10)
                })
        })
    {
        bail!("client oracle must emit ten shapes for each rail");
    }
    if vectors["errors"]["expected"]["variants"]
        .as_array()
        .is_none_or(|variants| variants.len() != 61)
    {
        bail!("client oracle must emit all 61 ClientError variants");
    }
    Ok(())
}

fn client_fixtures(root: &Path, vectors: &Value) -> Result<Vec<(&'static str, Value)>> {
    let domains = [
        (
            "errors",
            "client/errors-v1.json",
            "fx-p09-client-errors-v1",
            "sdk-libs/client/src/error.rs; sdk-libs/keypair/src/error.rs; sdk-libs/transaction/src/error.rs; program-libs/hasher/src/errors.rs",
            "ClientError; KeypairError; TransactionError; HasherError",
            "exhaustive client variant codes, structured fields, and representative wrapped categories",
        ),
        (
            "prover",
            "client/prover-shapes-v1.json",
            "fx-p00-client-prover-shapes-v1",
            "sdk-libs/client/src/prover/transact/witness.rs; sdk-libs/client/src/prover/transact/eddsa.rs; sdk-libs/client/src/prover/transact/p256_and_eddsa.rs; sdk-libs/client/src/prover/json.rs",
            "assemble; TransferProver::build; TransferP256Prover::build; ProverClient::{prove_transfer,prove_transfer_p256}",
            "complete EdDSA and P256 shape witnesses, prover JSON, and transact instruction bytes",
        ),
        (
            "proof",
            "client/proof-validity-v1.json",
            "fx-p00-client-proof-validity-v1",
            "sdk-libs/client/src/prover/proof.rs",
            "proof_from_gnark_json; ProofCompressed::try_from; ProofCompressed::to_transact_proof",
            "valid vanilla and BSB22 points, exact negation and compression, and rail errors",
        ),
        (
            "rpc",
            "client/rpc-indexer-v1.json",
            "fx-p00-client-rpc-indexer-v1",
            "sdk-libs/client/src/client.rs; sdk-libs/client/src/solana_rpc.rs; sdk-libs/client/src/indexer.rs",
            "build_unsigned_solana_transaction; transact_output_view_tags_from_instruction_groups; indexer::{convert_encrypted_utxo_match,convert_shielded_transaction,convert_merkle_proof,convert_non_inclusion_proof}; IndexerPollConfig::backoff",
            "legacy unsigned messages, owned indexer response values, confirmation tags, retries, and errors",
        ),
    ];
    let mut fixtures = domains
        .into_iter()
        .map(|(section, path, id, rust_path, symbol, responsibility)| {
            let value = &vectors[section];
            if !value.is_object() {
                bail!("client oracle lacks {section}");
            }
            Ok((
                path,
                fixture_base!(
                    id,
                    rust_path,
                    symbol,
                    "P09 fixture follow-up recorded in sdk-libs/ts/reports/packets/P09.json",
                    "P00",
                    responsibility,
                    value["inputs"].clone(),
                    value["expected"].clone(),
                ),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    fixtures.push(("client/lib.json", client_lib_fixture(root)?));
    Ok(fixtures)
}

/// Crate-root surface of `zolana-client`, so `@zolana/client` can prove it carries or dispositions
/// every name a Rust caller reaches through `use zolana_client::..`.
fn client_lib_fixture(root: &Path) -> Result<Value> {
    let source = fs::read_to_string(root.join("sdk-libs/client/src/lib.rs"))
        .context("read sdk-libs/client/src/lib.rs")?;
    let mut modules = Vec::new();
    let mut names = Vec::new();
    for statement in strip_line_comments(&source).split(';') {
        if let Some(item) = statement.split("pub mod ").nth(1) {
            modules.push(item.trim().to_string());
        } else if let Some(item) = statement.split("pub use ").nth(1) {
            push_use_tree_leaves(item, &mut names);
        }
    }
    modules.sort_unstable();
    modules.dedup();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        bail!("sdk-libs/client/src/lib.rs yielded no re-exports");
    }
    Ok(fixture_base!(
        "fx-p09-client-lib-v1",
        "sdk-libs/client/src/lib.rs",
        "pub mod; pub use",
        "P09 fixture follow-up recorded in sdk-libs/ts/reports/packets/P09.json",
        "P00",
        "the crate-root modules and re-exported names the TypeScript client must carry or disposition",
        json!({ "source": "sdk-libs/client/src/lib.rs" }),
        json!({ "modules": modules, "names": names }),
    ))
}

fn strip_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            Some(start) => &line[..start],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A `pub use` item is a tree: `a::{b, c::{d, e}}` re-exports the leaf names `b`, `d`, and `e`.
fn push_use_tree_leaves(item: &str, out: &mut Vec<String>) {
    let item = item.trim();
    match (item.find('{'), item.rfind('}')) {
        (Some(open), Some(close)) if open < close => {
            for branch in split_use_tree_branches(&item[open + 1..close]) {
                push_use_tree_leaves(&branch, out);
            }
        }
        _ => {
            let leaf = item.rsplit("::").next().unwrap_or(item).trim();
            if !leaf.is_empty() && leaf != "self" {
                out.push(leaf.to_string());
            }
        }
    }
}

fn split_use_tree_branches(group: &str) -> Vec<String> {
    let mut branches = Vec::new();
    let mut depth = 0usize;
    let mut branch = String::new();
    for character in group.chars() {
        match character {
            '{' => {
                depth += 1;
                branch.push(character);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                branch.push(character);
            }
            ',' if depth == 0 => branches.push(core::mem::take(&mut branch)),
            _ => branch.push(character),
        }
    }
    branches.push(branch);
    branches
        .into_iter()
        .filter(|branch| !branch.trim().is_empty())
        .collect()
}

fn instruction_workflow_fixtures(vectors: &Value) -> Result<Vec<(&'static str, Value)>> {
    let domains = [
        (
            "workflow_transfer",
            "workflows/instruction-transfer-v1.json",
            "fx-workflow-instruction-transfer-v1",
            "sdk-libs/transaction/src/instructions/transact/transfer.rs; sdk-libs/client/src/prover/transact; program-libs/interface/src/instruction/builders/transact.rs; sdk-libs/client/src/solana_rpc.rs",
            "ConfidentialTransfer::{prepare,send}; PreparedTransfer::finalize; assemble; ProverClient::{prove_transfer,prove_transfer_p256}; ProofCompressed::try_from; Transact::instruction; transact_output_view_tags_from_instruction_groups",
            "raw registered transfer across EdDSA, P256, and mixed-input rails with exact proof, wire, message, confirmation, state, and rejection evidence",
        ),
        (
            "workflow_withdraw_sol",
            "workflows/instruction-withdraw-sol-v1.json",
            "fx-workflow-instruction-withdraw-sol-v1",
            "sdk-libs/transaction/src/instructions/transact/transfer.rs; sdk-libs/client/src/prover/transact; program-libs/interface/src/instruction/builders/transact.rs; sdk-libs/client/src/solana_rpc.rs",
            "ConfidentialTransfer::{prepare,withdraw}; PreparedTransfer::finalize; assemble; ProverClient::prove_transfer; ProofCompressed::try_from; Transact::instruction; transact_output_view_tags_from_instruction_groups",
            "raw SOL withdrawal with exact signed public amount, settlement suffix, proof, wire, message, confirmation, state, and rejection evidence",
        ),
        (
            "workflow_withdraw_spl",
            "workflows/instruction-withdraw-spl-v1.json",
            "fx-workflow-instruction-withdraw-spl-v1",
            "sdk-libs/transaction/src/instructions/transact/transfer.rs; sdk-libs/client/src/prover/transact; program-libs/interface/src/instruction/builders/transact.rs; sdk-libs/client/src/solana_rpc.rs",
            "ConfidentialTransfer::{prepare,withdraw}; PreparedTransfer::finalize; assemble; ProverClient::prove_transfer_p256; ProofCompressed::try_from; Transact::instruction; transact_output_view_tags_from_instruction_groups",
            "raw mixed-input SPL withdrawal with exact signed public amount, CPI suffix, proof, wire, message, confirmation, state, and rejection evidence",
        ),
    ];
    domains
        .into_iter()
        .map(|(section, path, id, rust_path, symbol, responsibility)| {
            let value = &vectors[section];
            if !value.is_object() {
                bail!("client oracle lacks {section}");
            }
            Ok((
                path,
                fixture_base!(
                    id,
                    rust_path,
                    symbol,
                    "P13 fixture blocker in sdk-libs/ts/reports/packets/P13.json",
                    "P00",
                    responsibility,
                    value["inputs"].clone(),
                    value["expected"].clone(),
                ),
            ))
        })
        .collect()
}

fn production_wallet_vectors(root: &Path) -> Result<Value> {
    let artifacts = cargo_rlibs(root, &["build", "-p", "zolana-wallet"])?;
    let metadata: Value = serde_json::from_str(&command_text(
        root,
        "rustup",
        &[
            "run",
            "1.97.0",
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
        ],
    )?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cargo metadata lacks target_directory"))?,
    );
    let externs = [
        ("ark_bn254", "ark-bn254@0.5.0"),
        ("ark_ec", "ark-ec@0.5.0"),
        ("ark_ff", "ark-ff@0.5.0"),
        ("bincode", "bincode@1.3.3"),
        ("borsh", "borsh@1.7.0"),
        ("p256", "p256@0.13.2"),
        ("serde_json", "serde_json@1.0.150"),
        ("solana_account", "solana-account@3.4.0"),
        ("solana_address", "solana-address@2.6.1"),
        (
            "solana_compute_budget_interface",
            "solana-compute-budget-interface@3.0.0",
        ),
        ("solana_hash", "solana-hash@4.5.0"),
        ("solana_instruction", "solana-instruction@3.4.0"),
        ("solana_keypair", "solana-keypair@3.1.2"),
        ("solana_pubkey", "solana-pubkey@4.2.0"),
        ("solana_signature", "solana-signature@3.4.1"),
        ("solana_signer", "solana-signer@3.0.1"),
        ("solana_transaction", "solana-transaction@3.1.0"),
        ("zolana_client", "zolana-client@0.1.0"),
        ("zolana_interface", "zolana-interface@0.1.0"),
        ("zolana_keypair", "zolana-keypair@0.1.0"),
        ("zolana_transaction", "zolana-transaction@0.1.0"),
        (
            "zolana_user_registry_interface",
            "zolana-user-registry-interface@0.1.0",
        ),
        ("zolana_wallet", "zolana-wallet@0.1.0"),
    ]
    .into_iter()
    .map(|(name, package)| Ok((name, rlib(&artifacts, name, package)?)))
    .collect::<Result<Vec<_>>>()?;

    let binary = target.join("ts-fixtures-wallet");
    let mut compile = Command::new("rustup");
    compile
        .current_dir(root)
        .args([
            "run",
            "1.97.0",
            "rustc",
            "--edition=2021",
            "xtask/src/ts_fixtures_wallet.rs",
            "-L",
        ])
        .arg(format!(
            "dependency={}",
            target.join("debug/deps").display()
        ));
    for (name, path) in externs {
        compile
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = compile
        .arg("-o")
        .arg(&binary)
        .output()
        .context("compile production wallet fixture oracle")?;
    if !output.status.success() {
        bail!(
            "compile production wallet fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = Command::new(&binary)
        .output()
        .context("run production wallet fixture oracle")?;
    if !output.status.success() {
        bail!(
            "run production wallet fixture oracle: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let vectors: Value = serde_json::from_slice(&output.stdout)?;
    verify_wallet_vectors(&vectors)?;
    Ok(vectors)
}

fn verify_wallet_vectors(vectors: &Value) -> Result<()> {
    let sections = [
        "create_associated_token_account",
        "deposit",
        "mod",
        "submit",
        "transaction",
        "lib",
        "user_registry",
        "wallet_authority",
        "wallet_sync",
        "workflow_ata",
        "workflow_merge",
        "workflow_split",
    ];
    let object = vectors
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("wallet oracle is not an object"))?;
    if object.len() != sections.len() {
        bail!(
            "wallet oracle emitted {} sections, expected {}",
            object.len(),
            sections.len()
        );
    }
    for section in sections {
        if vectors[section]["inputs"]["testOnlySecret"] != true {
            bail!("{section} wallet fixture does not mark test secrets");
        }
    }
    if vectors["wallet_authority"]["expected"]["approvalRejection"]["p256SignSkipped"] != true
        || vectors["wallet_sync"]["expected"]["atomicFailure"]["walletUnchanged"] != true
    {
        bail!("wallet oracle self-check failed");
    }
    Ok(())
}

fn wallet_fixtures(vectors: &Value) -> Result<Vec<(&'static str, Value)>> {
    let domains = [
        (
            "create_associated_token_account",
            "wallet/create_associated_token_account.json",
            "fx-p00-wallet-create-associated-token-account-v1",
            "sdk-libs/wallet/src/actions/create_associated_token_account.rs",
            "create_associated_token_account; CreateAssociatedTokenAccount",
            "sdk-libs/wallet/src/actions/create_associated_token_account.rs",
            "canonical ATA address, idempotent instruction, account flags, and submitted transaction",
        ),
        (
            "deposit",
            "wallet/deposit.json",
            "fx-p00-wallet-deposit-v1",
            "sdk-libs/wallet/src/actions/deposit.rs",
            "Deposit; create_deposit; build_deposit_transaction_sync",
            "sdk-libs/wallet/src/actions/deposit.rs",
            "SOL and SPL routing, deterministic deposit material, instruction bytes, unsigned transaction, and errors",
        ),
        (
            "mod",
            "wallet/mod.json",
            "fx-p00-wallet-actions-mod-v1",
            "sdk-libs/wallet/src/actions/mod.rs",
            "wallet action re-exports",
            "sdk-libs/wallet/src/actions/mod.rs",
            "action export inventory and SOL/SPL routing boundary",
        ),
        (
            "submit",
            "wallet/submit.json",
            "fx-p00-wallet-submit-v1",
            "sdk-libs/wallet/src/actions/submit.rs",
            "MergeMaterial; submit_merge_transaction",
            "sdk-libs/wallet/src/actions/submit.rs",
            "merge material, proof and submission sequence, compute budget, and validation errors",
        ),
        (
            "transaction",
            "wallet/transaction.json",
            "fx-p00-wallet-transaction-v1",
            "sdk-libs/wallet/src/actions/transaction.rs; sdk-libs/wallet/tests/transaction.rs",
            "create_transfer_sync; create_withdrawal; create_split; create_merge; sign_shielded_transaction_sync",
            "sdk-libs/wallet/src/actions/transaction.rs; sdk-libs/wallet/tests/transaction.rs",
            "registered and public routing, input selection, split, merge, authority ordering, proof inputs, custody boundary, and frozen test expectations",
        ),
        (
            "lib",
            "wallet/lib.json",
            "fx-p00-wallet-lib-v1",
            "sdk-libs/wallet/src/lib.rs",
            "wallet root modules and re-exports",
            "sdk-libs/wallet/src/lib.rs",
            "root module surface, documented flow, and nested client/transaction errors",
        ),
        (
            "user_registry",
            "wallet/user_registry.json",
            "fx-p00-wallet-user-registry-v1",
            "sdk-libs/wallet/src/user_registry.rs",
            "build_registration_transaction_sync; resolved_address_from_record; recipient_confidential_view_tag_sync",
            "sdk-libs/wallet/src/user_registry.rs",
            "registration, current-record no-op, key rotation, record resolution, and public fallback",
        ),
        (
            "wallet_authority",
            "wallet/wallet_authority.json",
            "fx-p00-wallet-authority-v1",
            "sdk-libs/wallet/src/wallet_authority.rs; sdk-libs/transaction/src/wallet/authority.rs",
            "LocalWalletAuthority; WalletAuthority; SyncWalletAuthority",
            "sdk-libs/wallet/src/wallet_authority.rs",
            "sync material, deterministic P256 signature, encryption-before-approval, and rejection short circuit",
        ),
        (
            "wallet_sync",
            "wallet/wallet_sync.json",
            "fx-p00-wallet-sync-v1",
            "sdk-libs/wallet/src/wallet_sync.rs",
            "SyncWalletConfig; sync_wallet_with_config; balances; history",
            "sdk-libs/wallet/src/wallet_sync.rs",
            "sync config, atomic failure, idempotent state, balances, history, and indexer lag/abort/timeout errors",
        ),
    ];
    domains
        .into_iter()
        .map(
            |(section, path, id, rust_path, symbol, inventory_row, responsibility)| {
                let value = &vectors[section];
                if !value.is_object() {
                    bail!("wallet oracle lacks {section}");
                }
                Ok((
                    path,
                    fixture_base!(
                        id,
                        rust_path,
                        symbol,
                        inventory_row,
                        "P00",
                        responsibility,
                        value["inputs"].clone(),
                        value["expected"].clone(),
                    ),
                ))
            },
        )
        .collect()
}

fn workflow_fixtures(vectors: &Value) -> Result<Vec<(&'static str, Value)>> {
    let domains = [
        (
            "workflow_split",
            "workflows/action-split-v1.json",
            "fx-workflow-action-split-v1",
            "sdk-libs/wallet/src/actions/transaction.rs; sdk-libs/transaction/src/instructions/transact/split.rs",
            "create_split; sign_shielded_transaction_sync; ConfidentialSplit; PreparedSplit",
            "split creation, encrypted bundle, proof inputs, submission transition, conservation, and tamper rejection",
        ),
        (
            "workflow_merge",
            "workflows/action-merge-v1.json",
            "fx-workflow-action-merge-v1",
            "sdk-libs/wallet/src/actions/transaction.rs; sdk-libs/wallet/src/actions/submit.rs; sdk-libs/client/src/prover/merge.rs; program-libs/interface/src/instruction/builders/merge_transact.rs",
            "create_merge; MergeMaterial; MergeProver::build; MergeProofResult::instruction_data; MergeTransact::instruction",
            "merge preparation, enabled record, owner material, proof request material, exact submission, and state transition",
        ),
        (
            "workflow_ata",
            "workflows/action-ata-idempotent-v1.json",
            "fx-workflow-action-ata-idempotent-v1",
            "sdk-libs/wallet/src/actions/create_associated_token_account.rs; program-libs/interface/src/instruction/builders/create_associated_token_account.rs",
            "create_associated_token_account; CreateAssociatedTokenAccount::instruction",
            "first ATA creation, idempotent repeat, exact transactions, unchanged balance, and RPC error propagation",
        ),
    ];
    domains
        .into_iter()
        .map(|(section, path, id, rust_path, symbol, responsibility)| {
            let value = &vectors[section];
            if !value.is_object() {
                bail!("wallet oracle lacks {section}");
            }
            Ok((
                path,
                fixture_base!(
                    id,
                    rust_path,
                    symbol,
                    "P12-BLOCKER-FIXTURES in sdk-libs/ts/reports/packets/P12.json",
                    "P00",
                    responsibility,
                    value["inputs"].clone(),
                    value["expected"].clone(),
                ),
            ))
        })
        .collect()
}

fn error_json(error: &impl std::fmt::Debug) -> Value {
    let debug = format!("{error:?}");
    let code = debug
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or("Unknown")
        .to_string();
    json!({"code":code,"details":debug})
}

fn write_inventory_report(path: &Path, rows: &[InventoryRow], baseline: &str) -> Result<()> {
    let mut packet_counts = BTreeMap::<String, usize>::new();
    let mut disposition_counts = BTreeMap::<String, usize>::new();
    for row in rows {
        *packet_counts.entry(row.packet.clone()).or_default() += 1;
        *disposition_counts
            .entry(row.disposition.clone())
            .or_default() += 1;
    }
    let p00 = rows.iter().filter(|row| row.packet == "P00").count();
    if p00 != 7 {
        bail!("P00 owns {p00} inventory rows, expected 7");
    }
    write_json(
        path,
        &json!({
            "counts":{
                "duplicate":"0",
                "missing":"0",
                "rows":rows.len().to_string(),
                "unknownPackets":"0"
            },
            "dispositionCounts":disposition_counts,
            "frozenCommit":baseline,
            "packetCounts":packet_counts,
            "rows":rows.iter().map(|row| json!({
                "disposition":row.disposition,
                "fixtureResponsibility":row.fixture,
                "marker":row.marker,
                "packet":row.packet,
                "path":row.path,
                "responsibility":row.responsibility,
                "target":row.target,
                "testResponsibility":row.tests
            })).collect::<Vec<_>>(),
            "schema":"zolana-ts-inventory-v1"
        }),
    )
}

fn revision_compatibility() -> Value {
    json!({
        "baseline": {
            "compatibility": "Provenance stamp for baseline-family fixtures regenerated from working-tree sources. May diverge from frozenCommit (Q6): stamps do not gate regeneration. Independent of client and merkleTree.",
            "regenerationTrigger": "Regenerate when sdk-libs or program-libs sources that feed baseline fixtures change the produced bytes."
        },
        "client": {
            "compatibility": "Live stamp for client/errors-v1.json, client/lib.json, and client/rpc-indexer-v1.json. Each fixture sourceRevision must equal this pin. May diverge from baseline and frozenCommit.",
            "regenerationTrigger": "Advances only when a current-client fixture body changes; unrelated tip moves under sdk-libs/client/src do not invalidate or rewrite the stamp."
        },
        "interface": {
            "compatibility": "Provenance stamp for interface-family fixtures. Independent of client and merkleTree; may match baseline when both families last regenerated together.",
            "regenerationTrigger": "Regenerate when program-libs/interface or related sources change interface fixture bytes."
        },
        "merkleTree": {
            "compatibility": "Stamp for merkle-tree/paths-v1.json. That fixture's sourceRevision must equal this pin. Independent of baseline, client, and frozenCommit.",
            "regenerationTrigger": "Regenerate when sdk-libs/merkle-tree or hasher sources change path fixture bytes."
        },
        "driftReview": {
            "compatibility": "Reviewed regeneration against current working-tree Rust. finding must be no-body-drift or a named body-change finding with an accepted disposition. Does not move frozenCommit.",
            "regenerationTrigger": "Re-run ts-fixtures --check (and --current-client --check) whenever sdk-libs or program-libs sources that feed fixtures change; update reviewedAgainst/reviewedAt/finding."
        },
        "frozenCommit": {
            "compatibility": "Historical inventory, spec, and proving-key pin. Must equal historicalBaselineCommit and photonSchemaRevision. api/transport-v1.json sourceRevision must equal this pin. Staleness relative to tip is expected; body freshness is enforced by generator --check plus driftReview.",
            "mustAgreeWith": ["historicalBaselineCommit", "photonSchemaRevision"],
            "regenerationTrigger": "Change only when deliberately re-pinning the historical evidence set."
        },
        "historicalBaselineCommit": {
            "compatibility": "Historical baseline alias. Must equal frozenCommit.",
            "mustAgreeWith": ["frozenCommit"],
            "regenerationTrigger": "Same as frozenCommit."
        },
        "photonSchemaRevision": {
            "compatibility": "Photon schema identity for indexer transport fixtures. Must equal frozenCommit while the schema is frozen to that revision.",
            "mustAgreeWith": ["frozenCommit"],
            "regenerationTrigger": "Change when the Photon schema the fixtures encode moves off the historical pin."
        },
        "specSha256": {
            "compatibility": "SHA-256 of docs/spec.md at frozenCommit. A fixture claim that assumes a different spec digest is incompatible with this pin.",
            "regenerationTrigger": "Recompute when frozenCommit moves to a commit whose docs/spec.md differs."
        },
        "provingKeyRelease": {
            "compatibility": "lockPath plus lockSha256 of proving-keys.lock at frozenCommit. Proof fixtures that assume a different proving-key release are incompatible with this pin.",
            "regenerationTrigger": "Update when the proving-keys.lock blob at frozenCommit changes (key rotation recorded on that historical pin)."
        }
    })
}

fn write_manifest(
    root: &Path,
    fixtures: &Path,
    client_revision: &str,
    baseline: &str,
) -> Result<()> {
    let spec = git_blob(root, &format!("{baseline}:docs/spec.md"))?;
    let lock_path = "prover/server/prover/provingkeys/proving-keys.lock";
    let proving_lock = git_blob(root, &format!("{baseline}:{lock_path}"))?;
    let mut entries = fixture_entries(fixtures)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let rustc = command_text(root, "rustup", &["run", "1.97.0", "rustc", "--version"])
        .unwrap_or_else(|_| "rustc 1.97.0 (workspace pinned)".to_string());
    // driftReview is authored by the fixture-freshness review, not regenerated
    // from Rust sources. Preserve the committed object so --check does not
    // erase a reviewed finding when every fixture body still matches.
    let drift_review = committed_drift_review(root)?;
    let mut manifest = json!({
        "files":entries.into_iter().map(|(path, sha256)| json!({"path":path,"sha256":sha256})).collect::<Vec<_>>(),
        "canonicalSourceRevisions":{
            "baseline":BASELINE_SHA,
            "client":client_revision,
            "interface":INTERFACE_SHA,
            "merkleTree":MERKLE_SHA
        },
        "frozenCommit":baseline,
        "generatorCommand":GENERATOR_COMMAND,
        "historicalBaselineCommit":baseline,
        "photonSchemaRevision":baseline,
        "provingKeyRelease":{
            "lockPath":lock_path,
            "lockSha256":sha256(&proving_lock)
        },
        "revisionCompatibility": revision_compatibility(),
        "rust":{
            "packages":[
                {"features":["default","solana-rpc"],"name":"zolana-client"},
                {"features":["poseidon","sha256","keccak"],"name":"zolana-hasher"},
                {"features":["default"],"name":"zolana-indexer-api"},
                {"features":["default","tree","verifying-keys"],"name":"zolana-interface"},
                {"features":["default"],"name":"zolana-keypair"},
                {"features":["default"],"name":"zolana-merkle-tree"},
                {"features":["default"],"name":"zolana-program-test"},
                {"features":[],"name":"zolana-test-utils"},
                {"features":["parallel"],"name":"zolana-transaction"},
                {"features":["default"],"name":"zolana-wallet"},
                {"features":["default"],"name":"zolana-api"}
            ],
            "toolchain":rustc.trim()
        },
        "schema":FIXTURE_SCHEMA,
        "specSha256":sha256(&spec),
        "version":"1"
    });
    if let Some(review) = drift_review {
        manifest
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("manifest is not an object"))?
            .insert("driftReview".to_string(), review);
    }
    write_json(&fixtures.join("manifest.json"), &manifest)
}

fn committed_drift_review(root: &Path) -> Result<Option<Value>> {
    let path = root.join("sdk-libs/ts/fixtures/manifest.json");
    let Ok(bytes) = fs::read(&path) else {
        return Ok(None);
    };
    let manifest: Value = serde_json::from_slice(&bytes)?;
    Ok(manifest.get("driftReview").cloned())
}

fn write_packet_report(out: &Path, inventory: &[InventoryRow], baseline: &str) -> Result<()> {
    let p00_rows = inventory
        .iter()
        .filter(|row| row.packet == "P00")
        .map(|row| row.path.clone())
        .collect::<Vec<_>>();
    let entries = fixture_entries(&out.join("fixtures"))?;
    let mut changed_paths = entries
        .iter()
        .map(|(path, _)| format!("sdk-libs/ts/fixtures/{path}"))
        .collect::<Vec<_>>();
    changed_paths.extend([
        "sdk-libs/ts/config/historical-baseline-commit".to_string(),
        "sdk-libs/ts/fixtures/manifest.json".to_string(),
        "sdk-libs/ts/reports/inventory.json".to_string(),
        "sdk-libs/ts/reports/packets/P00.json".to_string(),
        "xtask/src/bin/ts-fixtures.rs".to_string(),
        "xtask/src/ts_fixtures_api.rs".to_string(),
        "xtask/src/ts_fixtures_keypair.rs".to_string(),
        "xtask/src/ts_fixtures_client.rs".to_string(),
        "xtask/src/ts_fixtures_merkle.rs".to_string(),
        "xtask/src/ts_fixtures_transaction.rs".to_string(),
        "xtask/src/ts_fixtures_wallet.rs".to_string(),
    ]);
    changed_paths.sort();
    write_json(
        &out.join("reports/packets/P00.json"),
        &json!({
            "apiDiff":{"added":[],"changed":[],"removed":[]},
            "commands":[
                {"command":"rustup run 1.97.0 cargo check -p xtask --bin ts-fixtures","exitStatus":"0","responsibility":"fixture generator compilation"},
                {"command":"rustup run 1.97.0 cargo test -p xtask --bin ts-fixtures","exitStatus":"0","responsibility":"inventory, fixture ID, secret marking, and canonical JSON tests"},
                {"command":"rustup run 1.97.0 cargo clippy -p xtask --bin ts-fixtures -- -D warnings","exitStatus":"0","responsibility":"fixture generator lint"},
                {"command":"rustup run 1.97.0 cargo fmt --all -- --check","exitStatus":"0","responsibility":"Rust formatting"},
                {"command":"rustup run 1.97.0 rustfmt --edition 2021 --check xtask/src/ts_fixtures_transaction.rs","exitStatus":"0","responsibility":"standalone transaction oracle formatting"},
                {"command":"rustup run 1.97.0 rustfmt --edition 2021 --check xtask/src/ts_fixtures_client.rs","exitStatus":"0","responsibility":"standalone client oracle formatting"},
                {"command":"rustup run 1.97.0 rustfmt --edition 2021 --check xtask/src/ts_fixtures_api.rs","exitStatus":"0","responsibility":"standalone API transport oracle formatting"},
                {"command":"rustup run 1.97.0 rustfmt --edition 2021 --check xtask/src/ts_fixtures_wallet.rs","exitStatus":"0","responsibility":"standalone wallet oracle formatting"},
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures","exitStatus":"0","responsibility":"fixture generation"},
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check","exitStatus":"0","responsibility":"deterministic regeneration and Rust verification"},
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures && rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check","exitStatus":"0","responsibility":"deterministic double generation"},
                {"command":"npm run test:vectors --workspace @zolana/keypair","exitStatus":"0","responsibility":"P04 vector baseline before fixture-loader follow-up"},
                {"command":"npm run test:vectors --workspace @zolana/transaction","exitStatus":"0","responsibility":"P05 vector baseline before production fixture-loader follow-up"},
                {"command":"npm run test:unit --workspace @zolana/interface && npm run test:vectors --workspace @zolana/interface","exitStatus":"0","responsibility":"current interface instruction and codec tests"},
                {"command":"npm run test:unit --workspace @zolana/transaction && npm run test:vectors --workspace @zolana/transaction","exitStatus":"0","responsibility":"current transaction preparation, wire, and vector tests"},
                {"command":"npm run test:unit --workspace @zolana/client","exitStatus":"0","responsibility":"current P09 RPC, indexer, proof, and polling tests"},
                {"command":"npm run test:vectors --workspace @zolana/client","exitStatus":"0","responsibility":"current P09 fixture tests"},
                {"command":"npm run test:unit --workspace @zolana/wallet","exitStatus":"0","responsibility":"current wallet unit and frozen deposit tests"},
                {"command":"npm run test:vectors --workspace @zolana/wallet","exitStatus":"0","responsibility":"manifest-backed wallet vector tests"},
                {"command":"npm run test:cross --workspace @zolana/wallet","exitStatus":"0","responsibility":"current wallet cross-surface tests"},
                {"command":"npm run test:unit --workspace @zolana/test-kit","exitStatus":"0","responsibility":"current private test-kit tests"},
                {"command":"npm run fixtures:check","exitStatus":"0","responsibility":"manifest hashes, secret marking, deterministic regeneration, and 182-row inventory validation"},
                {"command":"npm run build && npm run typecheck && npm run lint && npm run test:inventory && npm run test:exports && npm run test:dependencies && npm run api:check","exitStatus":"0","responsibility":"current package build, type, lint, inventory, exports, dependency, and API tests"},
                {"command":"cargo xtask ts-fixtures --check","exitStatus":"blocked","responsibility":"canonical command; existing xtask dispatch is outside P00 ownership"},
                {"command":"npm run test:inventory","exitStatus":"0","responsibility":"frozen 182-row inventory completeness and packet ownership"},
                {"command":"git diff --exit-code -- sdk-libs/ts/fixtures","exitStatus":"1 (expected)","responsibility":"reopened P00 adds wallet fixtures and updates the manifest"},
                {"command":"git diff --check","exitStatus":"0","responsibility":"whitespace validation"}
            ],
            "counts":{
                "fixtureFiles":entries.len().to_string(),
                "apiTransportErrorVectors":"5",
                "apiTransportSuccessVectors":"6",
                "clientFixtureFiles":"8",
                "inventoryDuplicate":"0",
                "inventoryMissing":"0",
                "inventoryRows":inventory.len().to_string(),
                "inventoryUnknownPackets":"0",
                "keypairFixtureFiles":"12",
                "transactionFixtureFiles":"14",
                "transactionOracleVectors":"13",
                "walletFixtureFiles":"10",
                "walletOracleVectors":"12",
                "workflowFixtureFiles":"7",
                "p00Rows":p00_rows.len().to_string()
            },
            "fixtureIds":fixture_ids(&out.join("fixtures"))?,
            "frozenCommit":baseline,
            "ownedChangedPaths":changed_paths,
            "packet":"P00",
            "p00InventoryRows":p00_rows,
            "p00RowEvidence":inventory.iter().filter(|row| row.packet == "P00").map(|row| json!({
                "disposition":row.disposition,
                "fixture":"none (explicit exclusion)",
                "path":row.path,
                "test":"test-inventory-exclusion-check"
            })).collect::<Vec<_>>(),
            "p04FollowUp":{
                "command":"npm run test:vectors --workspace @zolana/keypair",
                "fixtureFiles":[
                    "constants.json","encryption.json","error.json","hash.json","lib.json",
                    "merge.json","nullifier_key.json","pubkey.json","shielded.json",
                    "signing_key.json","tests.json","viewing_key.json"
                ],
                "testFile":"sdk-libs/ts/keypair/test/vectors/keypair-vectors.test.ts"
            },
            "p05FollowUp":{
                "command":"npm run test:vectors --workspace @zolana/transaction",
                "fixtureFiles":[
                    "asset-v1.json","authority-v1.json","data-v1.json","frozen-tests-v1.json",
                    "merge-v1.json","serialization-v1.json","split-v1.json","transact-v1.json",
                    "transfer-v1.json","utxo-v1.json","values-and-errors-v1.json",
                    "wallet-state-v1.json","wallet-sync-v1.json","zone-v1.json"
                ],
                "sharedFixtureFiles":[
                    "sdk-libs/ts/fixtures/client/proof-input-v1.json",
                    "sdk-libs/ts/fixtures/client/proof-result-compression-v1.json"
                ],
                "loaderChanges":[
                    "replace hard-coded Rust literals with manifest-verified reads from sdk-libs/ts/fixtures/transaction",
                    "parameterize codec tests over expected.families and assert exact bytes plus malformed errors",
                    "load transfer, split, merge, zone, proof-input, asset, authority, wallet-state, and wallet-sync snapshots by fixture id",
                    "replay frozen-tests-v1 regression seeds and assert sequential/parallel equivalence"
                ],
                "testFiles":[
                    "sdk-libs/ts/transaction/test/vectors/transaction-vectors.test.ts",
                    "sdk-libs/ts/transaction/test/serialization.test.ts",
                    "sdk-libs/ts/transaction/test/transfer.test.ts",
                    "sdk-libs/ts/transaction/test/wallet-sync.test.ts"
                ]
            },
            "p08FollowUp":{
                "fixture":"sdk-libs/ts/fixtures/api/transport-v1.json",
                "rustMethods":"5",
                "successCases":"6",
                "errorCases":"5",
                "testFile":"sdk-libs/ts/api/test/vectors.test.ts"
            },
            "p09FollowUp":{
                "blocker":"sdk-libs/ts/reports/packets/P09.json:10-59",
                "fixtureFiles":[
                    "sdk-libs/ts/fixtures/client/prover-shapes-v1.json",
                    "sdk-libs/ts/fixtures/client/proof-validity-v1.json",
                    "sdk-libs/ts/fixtures/client/rpc-indexer-v1.json"
                ],
                "groups":[
                    {
                        "fixture":"client/prover-shapes-v1.json",
                        "symbols":["prover::transact::witness::assemble","TransferProver::build","TransferP256Prover::build","ProverClient::{prove_transfer,prove_transfer_p256}"],
                        "tests":["client/test/vectors/prover-inputs.test.ts","client/test/prover/eddsa.test.ts","client/test/prover/p256.test.ts"]
                    },
                    {
                        "fixture":"client/proof-validity-v1.json",
                        "symbols":["proof_from_gnark_json","ProofCompressed::try_from","ProofCompressed::to_transact_proof"],
                        "tests":["client/test/vectors/proof-compression.test.ts","client/test/prover.test.ts"]
                    },
                    {
                        "fixture":"client/rpc-indexer-v1.json",
                        "symbols":["SolanaRpc RPC methods","indexer proof converters","build_unsigned_solana_transaction","wait_for_indexed_transaction_async"],
                        "tests":["client/test/solana-rpc.test.ts","client/test/indexer-client.test.ts","client/test/vectors/unsigned-message.test.ts"]
                    }
                ],
                "supportedShapesPerRail":"10"
            },
            "p10FollowUp":{
                "blocker":"sdk-libs/ts/reports/packets/P10.json fixture-generator blocker (labelled P01; owned by P00)",
                "fixtureFiles":[
                    "sdk-libs/ts/fixtures/wallet/create_associated_token_account.json",
                    "sdk-libs/ts/fixtures/wallet/deposit.json",
                    "sdk-libs/ts/fixtures/wallet/mod.json",
                    "sdk-libs/ts/fixtures/wallet/submit.json",
                    "sdk-libs/ts/fixtures/wallet/transaction.json",
                    "sdk-libs/ts/fixtures/wallet/lib.json",
                    "sdk-libs/ts/fixtures/wallet/user_registry.json",
                    "sdk-libs/ts/fixtures/wallet/wallet_authority.json",
                    "sdk-libs/ts/fixtures/wallet/wallet_sync.json"
                ],
                "inventoryMapping":[
                    {"fixture":"wallet/create_associated_token_account.json","rows":["sdk-libs/wallet/src/actions/create_associated_token_account.rs"]},
                    {"fixture":"wallet/deposit.json","rows":["sdk-libs/wallet/src/actions/deposit.rs"]},
                    {"fixture":"wallet/mod.json","rows":["sdk-libs/wallet/src/actions/mod.rs"]},
                    {"fixture":"wallet/submit.json","rows":["sdk-libs/wallet/src/actions/submit.rs"]},
                    {"fixture":"wallet/transaction.json","rows":["sdk-libs/wallet/src/actions/transaction.rs","sdk-libs/wallet/tests/transaction.rs"]},
                    {"fixture":"wallet/lib.json","rows":["sdk-libs/wallet/src/lib.rs"]},
                    {"fixture":"wallet/user_registry.json","rows":["sdk-libs/wallet/src/user_registry.rs"]},
                    {"fixture":"wallet/wallet_authority.json","rows":["sdk-libs/wallet/src/wallet_authority.rs"]},
                    {"fixture":"wallet/wallet_sync.json","rows":["sdk-libs/wallet/src/wallet_sync.rs"]}
                ],
                "targetTests":[
                    "sdk-libs/ts/wallet/test/vectors/wallet-vectors.test.ts",
                    "sdk-libs/ts/wallet/test/vectors/deposit-vector.test.ts"
                ]
            },
            "p12FollowUp":{
                "blocker":"P12-BLOCKER-FIXTURES",
                "fixtureMapping":[
                    {
                        "fixture":"sdk-libs/ts/fixtures/workflows/action-split-v1.json",
                        "id":"fx-workflow-action-split-v1",
                        "assertions":[
                            "auto-selected divisible input and exact conservation",
                            "encrypted split bundle and signed proof-input bytes",
                            "spent input plus resulting real and padding outputs",
                            "repeated sync no-op and spent-input tamper rejection"
                        ],
                        "test":"e2e-action-split"
                    },
                    {
                        "fixture":"sdk-libs/ts/fixtures/workflows/action-merge-v1.json",
                        "id":"fx-workflow-action-merge-v1",
                        "assertions":[
                            "smallest-first preparation and enabled user-record context",
                            "minimal merge material and deterministic proof inputs",
                            "exact merge instruction, account metas, message, signature, and output hash",
                            "spent inputs, one merged output, repeated sync no-op, and typed rejection paths"
                        ],
                        "test":"e2e-action-merge-submit"
                    },
                    {
                        "fixture":"sdk-libs/ts/fixtures/workflows/action-ata-idempotent-v1.json",
                        "id":"fx-workflow-action-ata-idempotent-v1",
                        "assertions":[
                            "canonical ATA and exact idempotent instruction",
                            "first and repeated submitted messages",
                            "single account creation and zero repeated balance delta",
                            "typed RPC submission error propagation"
                        ],
                        "test":"e2e-action-ata-idempotent"
                    }
                ],
                "sourceRevision":baseline
            },
            "p13FollowUp":{
                "blocker":"P00-owned missing workflow fixtures in sdk-libs/ts/reports/packets/P13.json",
                "fixtureMapping":[
                    {
                        "fixture":"sdk-libs/ts/fixtures/workflows/instruction-transfer-v1.json",
                        "id":"fx-workflow-instruction-transfer-v1",
                        "assertions":[
                            "raw registered transfer across EdDSA, P256, and mixed-input P256 rails",
                            "exact proof inputs, prover request/result/compression, transact accounts and bytes",
                            "exact unsigned messages, direct and inner confirmation tags, nullifiers, outputs, and balances",
                            "malformed and incomplete proof, wrong account order, wrong-signature timeout, owner-tag, and replay rejection evidence"
                        ],
                        "test":"e2e-instruction-transfer-wire"
                    },
                    {
                        "fixture":"sdk-libs/ts/fixtures/workflows/instruction-withdraw-sol-v1.json",
                        "id":"fx-workflow-instruction-withdraw-sol-v1",
                        "assertions":[
                            "negative public SOL amount and exact SOL-interface, recipient, and system-program suffix",
                            "exact EdDSA proof inputs, prover exchange, compression, transact bytes, and unsigned message",
                            "external SOL balance delta, input nullifiers, output commitments, and confirmation tags",
                            "malformed and incomplete proof, wrong account order, wrong-signature timeout, owner-tag, and replay rejection evidence"
                        ],
                        "test":"e2e-instruction-withdraw-sol-wire"
                    },
                    {
                        "fixture":"sdk-libs/ts/fixtures/workflows/instruction-withdraw-spl-v1.json",
                        "id":"fx-workflow-instruction-withdraw-spl-v1",
                        "assertions":[
                            "one negative public SPL asset and exact CPI-authority, vault, recipient, ATA, and token-program suffix",
                            "exact mixed-input P256 proof inputs, prover exchange, commitment compression, transact bytes, and unsigned message",
                            "external SPL balance delta, input nullifiers, output commitments, and confirmation tags",
                            "malformed and incomplete proof, wrong account order, wrong-signature timeout, and replay rejection evidence"
                        ],
                        "test":"e2e-instruction-withdraw-spl-wire"
                    }
                ],
                "sourceRevision":baseline
            },
            "schema":"zolana-ts-packet-evidence-v1"
        }),
    )
}

/// Stamp `frozenCommit` on every packet report without rewriting other fields.
/// Hand-authored P01–P13 keep their body; only the pin moves with the baseline.
fn stamp_packet_frozen_commits(packets_dir: &Path, baseline: &str) -> Result<()> {
    if !packets_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(packets_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let Some(updated) = replace_frozen_commit_value(&text, baseline) else {
            continue;
        };
        if updated != text {
            fs::write(&path, updated.as_bytes())
                .with_context(|| format!("write {}", path.display()))?;
        }
    }
    Ok(())
}

/// Replace every `"frozenCommit": "<40-hex>"` value in place. Returns `None`
/// when the file has no such field.
fn replace_frozen_commit_value(text: &str, baseline: &str) -> Option<String> {
    const KEY: &str = "\"frozenCommit\"";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut found = false;
    while let Some(key_at) = rest.find(KEY) {
        found = true;
        out.push_str(&rest[..key_at]);
        out.push_str(KEY);
        rest = &rest[key_at + KEY.len()..];
        let colon = rest.find(':')?;
        out.push_str(&rest[..=colon]);
        rest = &rest[colon + 1..];
        let quote_at = rest.find('"')?;
        out.push_str(&rest[..quote_at]);
        out.push('"');
        rest = &rest[quote_at + 1..];
        let end_quote = rest.find('"')?;
        let old = &rest[..end_quote];
        if old.len() != 40 || !old.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        out.push_str(baseline);
        out.push('"');
        rest = &rest[end_quote + 1..];
    }
    if !found {
        return None;
    }
    out.push_str(rest);
    Some(out)
}

fn verify_manifest(fixtures: &Path, client_revision: &str, baseline: &str) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&fs::read(fixtures.join("manifest.json"))?)?;
    if manifest["frozenCommit"] != baseline
        || manifest["historicalBaselineCommit"] != baseline
        || manifest["canonicalSourceRevisions"]["baseline"] != BASELINE_SHA
        || manifest["canonicalSourceRevisions"]["client"] != client_revision
        || manifest["canonicalSourceRevisions"]["interface"] != INTERFACE_SHA
        || manifest["canonicalSourceRevisions"]["merkleTree"] != MERKLE_SHA
        || manifest["schema"] != FIXTURE_SCHEMA
    {
        bail!("manifest provenance mismatch");
    }
    let files = manifest["files"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("manifest files is not an array"))?;
    let listed = files
        .iter()
        .map(|entry| {
            Ok((
                entry["path"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("manifest path is not a string"))?
                    .to_string(),
                entry["sha256"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("manifest sha256 is not a string"))?
                    .to_string(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if listed != fixture_entries(fixtures)? {
        bail!("manifest file set or hashes do not match fixtures");
    }
    let mut ids = BTreeSet::new();
    for entry in files {
        let relative = entry["path"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest path is not a string"))?;
        let bytes = fs::read(fixtures.join(relative))?;
        if sha256(&bytes) != entry["sha256"] {
            bail!("manifest hash mismatch for {relative}");
        }
        let fixture: Value = serde_json::from_slice(&bytes)?;
        for field in [
            "expected",
            "id",
            "inputs",
            "inventoryRow",
            "owningPacket",
            "responsibility",
            "rustPath",
            "rustSymbol",
            "schema",
            "version",
        ] {
            if fixture.get(field).is_none() {
                bail!("{relative} lacks {field}");
            }
        }
        if fixture["schema"] != FIXTURE_SCHEMA
            || fixture["version"] != "1"
            || fixture["owningPacket"] != "P00"
        {
            bail!("{relative} has invalid fixture provenance");
        }
        if matches!(
            relative,
            "client/proof-validity-v1.json"
                | "client/proof-result-compression-v1.json"
                | "client/proof-input-v1.json"
        ) {
            let keys = fixture["verifyingKeys"].as_array().ok_or_else(|| {
                anyhow::anyhow!("{relative} lacks verifyingKeys for proof provenance")
            })?;
            if keys.is_empty() {
                bail!("{relative} verifyingKeys is empty");
            }
            for key in keys {
                if key["module"].as_str().is_none_or(|m| m.is_empty())
                    || key["sha256"].as_str().is_none_or(|s| s.len() != 64)
                {
                    bail!("{relative} verifyingKeys entry lacks module or sha256");
                }
            }
        }
        let id = fixture["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{relative} fixture id is not a string"))?;
        if id.is_empty() || !ids.insert(id.to_string()) {
            bail!("{relative} has an empty or duplicate fixture id");
        }
    }
    if manifest.get("revisionCompatibility").is_none() {
        bail!("manifest lacks revisionCompatibility");
    }
    Ok(())
}

fn compare_outputs(generated: &Path, expected: &Path) -> Result<()> {
    compare_trees(&generated.join("fixtures"), &expected.join("fixtures"))?;
    for relative in ["reports/inventory.json", "reports/packets/P00.json"] {
        let actual = fs::read(generated.join(relative))?;
        let wanted = fs::read(expected.join(relative))?;
        if actual != wanted {
            bail!("generated content differs: {relative}");
        }
    }
    Ok(())
}

fn compare_trees(generated: &Path, expected: &Path) -> Result<()> {
    let generated_files = all_files(generated)?;
    let expected_files = all_files(expected)?;
    if generated_files != expected_files {
        bail!("generated file set differs from checked-in P00 outputs");
    }
    for relative in generated_files {
        let actual = fs::read(generated.join(&relative))?;
        let wanted = fs::read(expected.join(&relative))?;
        if actual != wanted {
            bail!("generated content differs: {}", relative.display());
        }
    }
    Ok(())
}

fn fixture_entries(fixtures: &Path) -> Result<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for relative in all_files(fixtures)? {
        if relative == Path::new("manifest.json") {
            continue;
        }
        let bytes = fs::read(fixtures.join(&relative))?;
        entries.push((
            relative.to_string_lossy().replace('\\', "/"),
            sha256(&bytes),
        ));
    }
    Ok(entries)
}

fn fixture_ids(fixtures: &Path) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for relative in all_files(fixtures)? {
        if relative == Path::new("manifest.json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(fixtures.join(relative))?)?;
        ids.push(value["id"].as_str().unwrap_or_default().to_string());
    }
    ids.sort();
    Ok(ids)
}

fn all_files(root: &Path) -> Result<BTreeSet<PathBuf>> {
    fn walk(base: &Path, dir: &Path, files: &mut BTreeSet<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(base, &path, files)?;
            } else {
                files.insert(path.strip_prefix(base)?.to_path_buf());
            }
        }
        Ok(())
    }
    let mut files = BTreeSet::new();
    if root.exists() {
        walk(root, root, &mut files)?;
    }
    Ok(files)
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let canonical = canonicalize(value);
    let mut bytes = serde_json::to_vec_pretty(&canonical)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let sorted = values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect::<Map<_, _>>())
        }
        _ => value.clone(),
    }
}

fn command_lines(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    if !output.status.success() {
        bail!("git {} failed", args.join(" "));
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .map(str::to_string)
        .collect())
}

fn command_text(root: &Path, command: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(command)
        .current_dir(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        bail!("{command} {} failed", args.join(" "));
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn git_blob(root: &Path, object: &str) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["show", object])
        .output()?;
    if !output.status.success() {
        bail!("git show {object} failed");
    }
    Ok(output.stdout)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_inventory_is_complete_and_unique() {
        let root = workspace_root().expect("workspace root");
        let rows = inventory(&root).expect("valid inventory");
        assert_eq!(rows.len(), 182);
        assert_eq!(rows.iter().filter(|row| row.packet == "P00").count(), 7);
        assert_eq!(
            rows.iter()
                .map(|row| row.path.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            182
        );
    }

    #[test]
    fn production_fixture_ids_are_unique_and_secrets_are_marked() {
        let root = workspace_root().expect("workspace root");
        let baseline = historical_baseline_commit(&root).expect("historical baseline");
        let (fixtures, _) = production_fixtures(&root, &baseline).expect("production fixtures");
        assert_eq!(fixtures.len(), EXPECTED_FIXTURE_COUNT);
        let ids = fixtures
            .iter()
            .map(|(_, value)| value["id"].as_str().expect("fixture id"))
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), EXPECTED_FIXTURE_COUNT);
        let (_, secret) = fixtures
            .iter()
            .find(|(path, _)| path.starts_with("keypair/"))
            .expect("keypair fixture");
        assert_eq!(secret["inputs"]["testOnlySecret"], true);
        for (path, fixture) in &fixtures {
            let encoded = serde_json::to_string(&fixture["inputs"]).expect("serialize inputs");
            let encoded = encoded.to_ascii_lowercase();
            if encoded.contains("blinding") || encoded.contains("secret") {
                assert_eq!(
                    fixture["inputs"]["testOnlySecret"], true,
                    "{path} contains test secret material without a marker"
                );
            }
        }
    }

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let value = json!({"z":{"b":2,"a":1},"a":0});
        let bytes = serde_json::to_vec(&canonicalize(&value)).expect("serialize");
        assert_eq!(bytes, br#"{"a":0,"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn current_client_stamp_is_excluded_from_body_equality() {
        let with_stamp = json!({
            "expected":{"ok":true},
            "id":"fx",
            "inputs":{},
            "sourceRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let other_stamp = json!({
            "expected":{"ok":true},
            "id":"fx",
            "inputs":{},
            "sourceRevision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        });
        let changed_body = json!({
            "expected":{"ok":false},
            "id":"fx",
            "inputs":{},
            "sourceRevision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        assert_eq!(fixture_body(&with_stamp), fixture_body(&other_stamp));
        assert_ne!(fixture_body(&with_stamp), fixture_body(&changed_body));
    }
}
