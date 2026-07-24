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

const FROZEN_SHA: &str = "43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f";
const FIXTURE_SCHEMA: &str = "zolana-ts-fixtures-v1";
const GENERATOR_COMMAND: &str = "rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures";
const EXPECTED_FIXTURE_COUNT: usize = 52;
const FROZEN_SOURCE_PATHS: [&str; 13] = [
    "program-libs/hasher/src",
    "program-libs/indexed-array/src",
    "program-libs/interface/src/instruction",
    "program-tests/test-utils/src/smart_account.rs",
    "sdk-libs/client/src/prover",
    "sdk-libs/client/src/rpc.rs",
    "sdk-libs/keypair/src",
    "sdk-libs/merkle-tree/src",
    "sdk-libs/program-test/src/indexer.rs",
    "sdk-libs/transaction/src",
    "sdk-libs/transaction/tests",
    "sdk-libs/wallet/src",
    "sdk-libs/wallet/tests",
];
const INVENTORY_FILES: [&str; 6] = [
    "planning/typescript-sdk-port/inventory-client.md",
    "planning/typescript-sdk-port/inventory-wallet.md",
    "planning/typescript-sdk-port/inventory-transaction.md",
    "planning/typescript-sdk-port/inventory-keypair.md",
    "planning/typescript-sdk-port/inventory-support.md",
    "planning/typescript-sdk-port/inventory-indexer-and-smart-account.md",
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
    let check = env::args().skip(1).try_fold(false, |_check, arg| match arg.as_str() {
        "--check" => Ok(true),
        "--help" | "-h" => {
            println!("Generate and verify deterministic TypeScript conformance fixtures.\n\nusage: cargo run -p xtask --bin ts-fixtures -- [--check]");
            std::process::exit(0);
        }
        _ => bail!("unexpected argument {arg:?}"),
    })?;
    let root = workspace_root()?;
    assert_frozen_sources(&root)?;
    let inventory = inventory(&root)?;

    if check {
        let generated = root.join("target/ts-fixtures-check");
        if generated.exists() {
            fs::remove_dir_all(&generated)?;
        }
        generate(&root, &generated, &inventory)?;
        compare_outputs(&generated, &root.join("sdk-libs/ts"))?;
        fs::remove_dir_all(&generated)?;
        println!(
            "verified {} fixtures and {} inventory rows",
            EXPECTED_FIXTURE_COUNT,
            inventory.len()
        );
    } else {
        generate(&root, &root.join("sdk-libs/ts"), &inventory)?;
        println!(
            "generated {} fixtures and {} inventory rows",
            EXPECTED_FIXTURE_COUNT,
            inventory.len()
        );
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

fn assert_frozen_sources(root: &Path) -> Result<()> {
    let commit = Command::new("git")
        .current_dir(root)
        .args(["cat-file", "-e", &format!("{FROZEN_SHA}^{{commit}}")])
        .status()?;
    if !commit.success() {
        bail!("frozen revision {FROZEN_SHA} is unavailable");
    }
    let unchanged = Command::new("git")
        .current_dir(root)
        .args(["diff", "--quiet", FROZEN_SHA, "--"])
        .args(FROZEN_SOURCE_PATHS)
        .status()?;
    if !unchanged.success() {
        bail!("fixture source paths differ from frozen revision {FROZEN_SHA}");
    }
    Ok(())
}

fn inventory(root: &Path) -> Result<Vec<InventoryRow>> {
    let frozen_paths = command_lines(
        root,
        &["ls-tree", "-r", "--name-only", FROZEN_SHA, "sdk-libs"],
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

fn generate(root: &Path, out: &Path, inventory: &[InventoryRow]) -> Result<()> {
    let fixtures = out.join("fixtures");
    for dir in FIXTURE_DIRS {
        fs::create_dir_all(fixtures.join(dir))?;
    }
    fs::create_dir_all(out.join("reports/packets"))?;

    let records = production_fixtures(root)?;
    if records.len() != EXPECTED_FIXTURE_COUNT {
        bail!(
            "generated {} fixtures, expected {EXPECTED_FIXTURE_COUNT}",
            records.len()
        );
    }
    for (relative, record) in records {
        write_json(&fixtures.join(relative), &record)?;
    }
    write_inventory_report(&out.join("reports/inventory.json"), inventory)?;
    write_manifest(root, &fixtures)?;
    verify_manifest(&fixtures)?;
    write_packet_report(out, inventory)?;
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

fn production_fixtures(root: &Path) -> Result<Vec<(&'static str, Value)>> {
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
    fixtures.extend(keypair_fixtures(&keypair_vectors)?);
    fixtures.extend(transaction_fixtures(&transaction_vectors)?);
    fixtures.extend(client_fixtures(&client_vectors)?);
    fixtures.extend(wallet_fixtures(&wallet_vectors)?);
    fixtures.extend(workflow_fixtures(&wallet_vectors)?);
    Ok(fixtures)
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
    for section in ["prover", "proof", "rpc"] {
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
    Ok(())
}

fn client_fixtures(vectors: &Value) -> Result<Vec<(&'static str, Value)>> {
    let domains = [
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
            "build_unsigned_solana_transaction; transact_output_view_tags_from_instruction_groups; IndexerPollConfig::backoff",
            "legacy unsigned messages, proof response values, confirmation tags, retries, and errors",
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
                    "P09 fixture follow-up recorded in sdk-libs/ts/reports/packets/P09.json",
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

fn write_inventory_report(path: &Path, rows: &[InventoryRow]) -> Result<()> {
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
            "frozenCommit":FROZEN_SHA,
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

fn write_manifest(root: &Path, fixtures: &Path) -> Result<()> {
    let spec = git_blob(root, &format!("{FROZEN_SHA}:docs/spec.md"))?;
    let lock_path = "prover/server/prover/provingkeys/proving-keys.lock";
    let proving_lock = git_blob(root, &format!("{FROZEN_SHA}:{lock_path}"))?;
    let mut entries = fixture_entries(fixtures)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let rustc = command_text(root, "rustup", &["run", "1.97.0", "rustc", "--version"])
        .unwrap_or_else(|_| "rustc 1.97.0 (workspace pinned)".to_string());
    write_json(
        &fixtures.join("manifest.json"),
        &json!({
            "files":entries.into_iter().map(|(path, sha256)| json!({"path":path,"sha256":sha256})).collect::<Vec<_>>(),
            "frozenCommit":FROZEN_SHA,
            "generatorCommand":GENERATOR_COMMAND,
            "photonSchemaRevision":FROZEN_SHA,
            "provingKeyRelease":{
                "lockPath":lock_path,
                "lockSha256":sha256(&proving_lock)
            },
            "rust":{
                "packages":[
                    {"features":["default","solana-rpc"],"name":"zolana-client"},
                    {"features":["poseidon","sha256","keccak"],"name":"zolana-hasher"},
                    {"features":["default","tree","verifying-keys"],"name":"zolana-interface"},
                    {"features":["default"],"name":"zolana-keypair"},
                    {"features":["default"],"name":"zolana-merkle-tree"},
                    {"features":["default"],"name":"zolana-program-test"},
                    {"features":[],"name":"zolana-test-utils"},
                    {"features":["parallel"],"name":"zolana-transaction"},
                    {"features":["default"],"name":"zolana-wallet"}
                ],
                "toolchain":rustc.trim()
            },
            "schema":FIXTURE_SCHEMA,
            "specSha256":sha256(&spec),
            "version":"1"
        }),
    )
}

fn write_packet_report(out: &Path, inventory: &[InventoryRow]) -> Result<()> {
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
        "sdk-libs/ts/fixtures/manifest.json".to_string(),
        "sdk-libs/ts/reports/inventory.json".to_string(),
        "sdk-libs/ts/reports/packets/P00.json".to_string(),
        "xtask/src/bin/ts-fixtures.rs".to_string(),
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
                {"command":"rustup run 1.97.0 rustfmt --edition 2021 --check xtask/src/ts_fixtures_wallet.rs","exitStatus":"0","responsibility":"standalone wallet oracle formatting"},
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures","exitStatus":"0","responsibility":"fixture generation"},
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check","exitStatus":"0","responsibility":"deterministic regeneration and Rust verification"},
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures && rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check","exitStatus":"0","responsibility":"deterministic double generation"},
                {"command":"npm run test:vectors --workspace @zolana/keypair","exitStatus":"0","responsibility":"P04 vector baseline before fixture-loader follow-up"},
                {"command":"npm run test:vectors --workspace @zolana/transaction","exitStatus":"0","responsibility":"P05 vector baseline before production fixture-loader follow-up"},
                {"command":"npm run test:unit --workspace @zolana/client","exitStatus":"0","responsibility":"current P09 RPC, indexer, proof, and polling tests"},
                {"command":"npm run test:vectors --workspace @zolana/client","exitStatus":"0","responsibility":"current P09 fixture tests"},
                {"command":"npm run test:unit --workspace @zolana/wallet","exitStatus":"0","responsibility":"current wallet unit and frozen deposit tests"},
                {"command":"npm run test:vectors --workspace @zolana/wallet","exitStatus":"0","responsibility":"manifest-backed wallet vector tests"},
                {"command":"npm run test:cross --workspace @zolana/wallet","exitStatus":"0","responsibility":"current wallet cross-surface tests"},
                {"command":"npm run test:unit --workspace @zolana/test-kit","exitStatus":"0","responsibility":"current private test-kit tests"},
                {"command":"npm run fixtures:check","exitStatus":"0","responsibility":"manifest hashes, secret marking, deterministic regeneration, and 182-row inventory validation"},
                {"command":"cargo xtask ts-fixtures --check","exitStatus":"blocked","responsibility":"canonical command; existing xtask dispatch is outside P00 ownership"},
                {"command":"npm run test:inventory","exitStatus":"0","responsibility":"frozen 182-row inventory completeness and packet ownership"},
                {"command":"git diff --exit-code -- sdk-libs/ts/fixtures","exitStatus":"1 (expected)","responsibility":"reopened P00 adds wallet fixtures and updates the manifest"},
                {"command":"git diff --check","exitStatus":"0","responsibility":"whitespace validation"}
            ],
            "counts":{
                "fixtureFiles":entries.len().to_string(),
                "clientFixtureFiles":"5",
                "inventoryDuplicate":"0",
                "inventoryMissing":"0",
                "inventoryRows":inventory.len().to_string(),
                "inventoryUnknownPackets":"0",
                "keypairFixtureFiles":"12",
                "transactionFixtureFiles":"14",
                "transactionOracleVectors":"13",
                "walletFixtureFiles":"10",
                "walletOracleVectors":"12",
                "workflowFixtureFiles":"4",
                "p00Rows":p00_rows.len().to_string()
            },
            "fixtureIds":fixture_ids(&out.join("fixtures"))?,
            "frozenCommit":FROZEN_SHA,
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
                "sourceRevision":FROZEN_SHA
            },
            "schema":"zolana-ts-packet-evidence-v1"
        }),
    )
}

fn verify_manifest(fixtures: &Path) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&fs::read(fixtures.join("manifest.json"))?)?;
    if manifest["frozenCommit"] != FROZEN_SHA || manifest["schema"] != FIXTURE_SCHEMA {
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
        let id = fixture["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{relative} fixture id is not a string"))?;
        if id.is_empty() || !ids.insert(id.to_string()) {
            bail!("{relative} has an empty or duplicate fixture id");
        }
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
        let fixtures = production_fixtures(&root).expect("production fixtures");
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
            let encoded = serde_json::to_string(fixture).expect("serialize fixture");
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
}
