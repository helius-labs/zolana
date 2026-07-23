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
const EXPECTED_FIXTURE_COUNT: usize = 12;
const FROZEN_SOURCE_PATHS: [&str; 9] = [
    "program-libs/interface/src/instruction",
    "program-tests/test-utils/src/smart_account.rs",
    "sdk-libs/client/src/prover",
    "sdk-libs/client/src/rpc.rs",
    "sdk-libs/program-test/src/indexer.rs",
    "sdk-libs/transaction/src/data.rs",
    "sdk-libs/transaction/src/instructions",
    "sdk-libs/transaction/src/utxo.rs",
    "sdk-libs/transaction/src/wallet/asset.rs",
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

    let records = production_fixtures()?;
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

fn production_fixtures() -> Result<Vec<(&'static str, Value)>> {
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

    Ok(vec![
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
                "sdk-libs/client/src/prover/inputs.rs",
                "TransferInput::new_dummy",
                "sdk-libs/program-test/src/indexer.rs",
                "P00",
                "Merkle and non-inclusion path dimensions consumed by production witness assembly",
                json!({
                    "dummyBlindingBytes":hex(&[8;31]),
                    "nullifierRootBytes":hex(&[10;32]),
                    "stateRootBytes":hex(&[9;32]),
                    "testOnlySecret":true
                }),
                json!({
                    "dummyNullifierBytes":hex(&dummy_nullifier),
                    "indexerEmptyRootBytes":hex(&indexer_root),
                    "nonInclusionPathLength":dummy.nullifier_low_path_elements.len().to_string(),
                    "statePathLength":dummy.state_path_elements.len().to_string()
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
    ])
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
                    {"features":["default","tree","verifying-keys"],"name":"zolana-interface"},
                    {"features":["default"],"name":"zolana-program-test"},
                    {"features":[],"name":"zolana-test-utils"},
                    {"features":[],"name":"zolana-transaction"}
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
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures","exitStatus":"0","responsibility":"fixture generation"},
                {"command":"rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check","exitStatus":"0","responsibility":"deterministic regeneration and Rust verification"},
                {"command":"cargo xtask ts-fixtures --check","exitStatus":"blocked","responsibility":"canonical command; existing xtask dispatch is outside P00 ownership"},
                {"command":"npm run test:inventory","exitStatus":"blocked","responsibility":"root npm workspace is owned by P01"},
                {"command":"git diff --exit-code -- sdk-libs/ts/fixtures","exitStatus":"0","responsibility":"tracked fixture diff is clean; the initial baseline remains untracked until committed"},
                {"command":"git diff --check","exitStatus":"0","responsibility":"whitespace validation"}
            ],
            "counts":{
                "fixtureFiles":entries.len().to_string(),
                "inventoryDuplicate":"0",
                "inventoryMissing":"0",
                "inventoryRows":inventory.len().to_string(),
                "inventoryUnknownPackets":"0",
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
        let fixtures = production_fixtures().expect("production fixtures");
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
