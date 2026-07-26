//! Prover request snapshots for proof certification suite P2.
//!
//! For each public-input case in the P1 matrix that TypeScript can serialize,
//! this binary captures the JSON body the production `ProverClient` sends by
//! calling the same `to_json*` serializers the live client uses. Hand-authored
//! expected JSON is forbidden: the fixture is the serializer output.
//!
//! Confidential full-shape requests already live in `prover-shapes-v1.json`
//! (same seeds). Zone full-shape requests live in the zone oracle (same seeds
//! as P1 zone). This fixture records the protocol revision, the per-circuit
//! key sets, the mixed-owner request bodies P1 added, one representative body
//! per circuit type, and the address-append shape TypeScript has no path for.
//!
//! ```text
//! cargo run -p xtask --bin prover-request            # write the fixture
//! cargo run -p xtask --bin prover-request -- --check  # fail on any drift
//! ```

use std::{
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
    sync::mpsc,
    thread,
};

use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use p256::SecretKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_address::Address;
use zolana_client::{
    assemble, attach_input_proofs, BatchAddressAppendInputs, MergeProver, MergeWitness,
    MergeZoneProver, MergeZoneWitness, MerkleContext, MerkleProof, NonInclusionProof, P256Owner,
    ProverClient, ProverInputs, PublicAmounts, SpendProof, TransferInputs, TransferP256Inputs,
    ZoneAuthorityProver, ZoneTransferP256Prover, ZoneTransferProver,
};
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{NullifierKey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        merge::PreparedMerge,
        merge_zone::PreparedMergeZone,
        transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    Data, Utxo, SOL_MINT,
};

const FIXTURE: &str = "sdk-libs/ts/vectors/prover-request-parity-v1.json";
const JSON_RS: &str = "sdk-libs/client/src/prover/json.rs";

const P256_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const ED25519_SECRET: [u8; 32] = [31; 32];
const VIEWING_SEED: [u8; 32] = [32; 32];
const BLINDING_SEED: [u8; 31] = [33; 31];

const ZONE_ED25519_SECRET: [u8; 32] = [61; 32];
const ZONE_VIEWING_SEED: [u8; 32] = [62; 32];
const ZONE_BLINDING_SEED: [u8; 31] = [63; 31];
const ZONE_PROGRAM: [u8; 32] = [64; 32];
const ZONE_PAYER: [u8; 32] = [66; 32];
const ZONE_TREE: [u8; 32] = [67; 32];
const ZONE_USER_SOL: [u8; 32] = [68; 32];
const ZONE_INPUT_AMOUNT: u64 = 100;

const MERGE_SIGNING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const MERGE_VIEWING_SEED: [u8; 32] = [8; 32];
const MERGE_BLINDING_SEED: [u8; 31] = [11; 31];
const MERGE_TX_VIEWING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15,
];
const MERGE_REAL_AMOUNTS: [u64; 2] = [10, 20];
const MERGE_OUTPUT_AMOUNT: u64 = 30;
const MERGE_INPUTS: usize = 8;
const MERGE_TREE: &str = "4WnNSfDXkWSnFi1PgXxn8X8fhFwU2Jhe4Df82mL9rKmm";
const MERGE_ZONE_PROGRAM: [u8; 32] = [3; 32];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("prover-request failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut check = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "Generate prover request parity snapshots.\n\nusage: cargo run -p xtask --bin prover-request -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    let path = workspace_root()?.join(FIXTURE);
    // Do not BTreeMap-canonicalize request bodies: serde field order is part of
    // the wire contract the TypeScript serializer mirrors.
    let fixture = fixture()?;
    let rendered = format!("{}\n", serde_json::to_string_pretty(&fixture)?);

    if check {
        let current = fs::read_to_string(&path)
            .with_context(|| format!("{FIXTURE} is missing; run the generator without --check"))?;
        if current != rendered {
            bail!("{FIXTURE} differs from production serializers; regenerate it");
        }
        println!("verified {FIXTURE}");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, rendered).with_context(|| format!("write {FIXTURE}"))?;
    println!("wrote {FIXTURE}");
    Ok(())
}

fn fixture() -> Result<Value> {
    let eddsa = capture_confidential(false)?;
    let p256 = capture_confidential(true)?;
    let zone = capture_zone()?;
    let zone_p256 = capture_zone_p256()?;
    let zone_authority = capture_zone_authority()?;
    let merge = capture_merge(false)?;
    let merge_zone = capture_merge(true)?;
    let address_append = capture_address_append()?;
    let mixed = capture_mixed_confidential()?;
    let zone_mixed = capture_zone_mixed()?;

    Ok(json!({
        "schemaVersion": "1",
        "fixtureVersion": "1",
        "fixtureId": "fx-p2-prover-request-parity-v1",
        "canonicalSourcePath": JSON_RS,
        "canonicalSourceSymbol": "to_json; to_json_p256; to_json_zone; to_json_p256_zone; to_json_zone_authority; to_json_merge; to_json_merge_zone; to_json_batch_address_append",
        "specificationSection": "planning/typescript-sdk-port/proof-and-key-parity.md#p2-prover-request-parity",
        "inventoryReviewRow": "P2",
        "proverProtocolRevision": protocol_revision()?,
        "circuitTypes": [
            "transfer-confidential",
            "transfer-p256-confidential",
            "transfer-zone",
            "transfer-p256-zone",
            "transfer-zone-authority",
            "merge",
            "merge-zone",
            "address-append",
        ],
        "typescriptPaths": {
            "transfer-confidential": true,
            "transfer-p256-confidential": true,
            "transfer-zone": true,
            "transfer-p256-zone": true,
            "transfer-zone-authority": true,
            "merge": true,
            "merge-zone": true,
            "address-append": false,
        },
        "knownKeys": {
            "transfer-confidential": object_keys(&eddsa)?,
            "transfer-p256-confidential": object_keys(&p256)?,
            "transfer-zone": object_keys(&zone)?,
            "transfer-p256-zone": object_keys(&zone_p256)?,
            "transfer-zone-authority": object_keys(&zone_authority)?,
            "merge": object_keys(&merge)?,
            "merge-zone": object_keys(&merge_zone)?,
            "address-append": object_keys(&address_append)?,
        },
        "p256Keys": ["p256PubX", "p256PubY", "p256SigR", "p256SigS", "p256MessageHashLow", "p256MessageHashHigh", "p256SigningPkField"],
        "inputs": {
            "blindingSeedBytes": hex(BLINDING_SEED),
            "ed25519SecretBytes": hex(ED25519_SECRET),
            "p256SecretBytes": hex(P256_SECRET),
            "viewingSeedBytes": hex(VIEWING_SEED),
            "testOnlySecret": true,
        },
        "expected": {
            "representatives": {
                "transfer-confidential": {"requestBodyJson": eddsa},
                "transfer-p256-confidential": {"requestBodyJson": p256},
                "transfer-zone": {"requestBodyJson": zone},
                "transfer-p256-zone": {"requestBodyJson": zone_p256},
                "transfer-zone-authority": {"requestBodyJson": zone_authority},
                "merge": {"requestBodyJson": merge},
                "merge-zone": {"requestBodyJson": merge_zone},
                "address-append": {"requestBodyJson": address_append},
            },
            "mixedOwner": {"requestBodyJson": mixed},
            "zoneMixedOwner": {"requestBodyJson": zone_mixed},
            "foldedCoverage": {
                "confidentialShapes": "sdk-libs/ts/fixtures/client/prover-shapes-v1.json#expected.rails[*].shapes[*].proverJson",
                "zoneShapes": "sdk-libs/ts/client/test/oracles/zone-v1.json#expected.*.[*].requestBodyJson",
                "merge": "sdk-libs/ts/client/test/oracles/merge-v1.json#expected.*.requestBodyJson",
            }
        }
    }))
}

fn protocol_revision() -> Result<String> {
    let bytes =
        fs::read(workspace_root()?.join(JSON_RS)).with_context(|| format!("read {JSON_RS}"))?;
    Ok(hex(Sha256::digest(bytes)))
}

fn object_keys(body: &str) -> Result<Vec<String>> {
    // Top-level keys in encounter order from the raw serializer output.
    let mut keys = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    let mut expecting_key = true;
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let byte = bytes[i];
        if in_string {
            if escape {
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match byte {
            b'"' if depth == 1 && expecting_key => {
                let start = i + 1;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                keys.push(std::str::from_utf8(&bytes[start..i])?.to_string());
                expecting_key = false;
            }
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if byte == b'{' && depth == 1 {
                    expecting_key = true;
                }
            }
            b'}' | b']' => depth -= 1,
            b':' if depth == 1 => expecting_key = false,
            b',' if depth == 1 => expecting_key = true,
            _ => {}
        }
        i += 1;
    }
    if keys.is_empty() {
        bail!("request body has no keys");
    }
    Ok(keys)
}

fn capture_confidential(p256: bool) -> Result<String> {
    let (inputs, proofs) = confidential_inputs(p256, 1, 1)?;
    let assembled = assemble(inputs, &proofs)?;
    capture_prover_inputs(&assembled.prover_inputs)
}

fn capture_mixed_confidential() -> Result<String> {
    let (p256_inputs, p256_proofs) = confidential_inputs(true, 2, 2)?;
    let (eddsa_inputs, _) = confidential_inputs(false, 1, 1)?;
    let p256_input = p256_inputs.input_utxos[0].clone();
    let eddsa_input = eddsa_inputs.input_utxos[0].clone();
    let mut mixed = SppProofInputs::new(
        vec![p256_input, eddsa_input.clone()],
        p256_inputs.output_utxos.clone(),
        p256_inputs.external_data.clone(),
        Address::new_from_array([44; 32]),
    );
    mixed.p256_signature = p256_inputs.p256_signature;
    let eddsa_hash = eddsa_input.hash()?;
    let eddsa_nullifier = eddsa_input.nullifier()?;
    let tree = Address::new_from_array([45; 32]);
    let proofs = vec![
        p256_proofs[0].clone(),
        SpendProof {
            state: MerkleProof {
                leaf: eddsa_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(47); 32],
                leaf_index: 1,
                root: field_byte(47),
                root_seq: 48,
                root_index: 50,
            },
            nullifier: NonInclusionProof {
                leaf: eddsa_nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(51); 40],
                low_element: field_byte(51),
                low_element_index: 0,
                high_element: field_byte(52),
                high_element_index: 1,
                root: field_byte(53),
                root_seq: 54,
                root_index: 56,
            },
        },
    ];
    let assembled = assemble(mixed, &proofs)?;
    capture_prover_inputs(&assembled.prover_inputs)
}

fn capture_zone() -> Result<String> {
    let owner = zone_keypair(false)?;
    let inputs = zone_proof_inputs(&owner, 1, 1);
    let proofs = zone_spend_proofs(&inputs)?;
    let spends = attach_input_proofs(inputs.input_utxos.clone(), &proofs)?;
    let result = ZoneTransferProver {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: zone_amounts(&inputs)?,
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        zone_program_id: Some(Address::new_from_array(ZONE_PROGRAM)),
        shape: None,
    }
    .build()?;
    capture_transfer(&result.inputs, CaptureKind::Zone)
}

fn capture_zone_p256() -> Result<String> {
    let owner = zone_keypair(true)?;
    let mut inputs = zone_proof_inputs(&owner, 1, 1);
    let p256 = zone_p256_owner(&owner, &mut inputs);
    let proofs = zone_spend_proofs(&inputs)?;
    let spends = attach_input_proofs(inputs.input_utxos.clone(), &proofs)?;
    let result = ZoneTransferP256Prover {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: zone_amounts(&inputs)?,
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        p256_owner: p256,
        zone_program_id: Some(Address::new_from_array(ZONE_PROGRAM)),
        shape: None,
    }
    .build()?;
    capture_transfer_p256(&result.inputs, CaptureKind::ZoneP256)
}

fn capture_zone_authority() -> Result<String> {
    let owner = zone_keypair(false)?;
    let inputs = zone_proof_inputs(&owner, 1, 1);
    let proofs = zone_spend_proofs(&inputs)?;
    let spends = attach_input_proofs(inputs.input_utxos.clone(), &proofs)?;
    let result = ZoneAuthorityProver {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: zone_amounts(&inputs)?,
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        zone_program_id: Some(Address::new_from_array(ZONE_PROGRAM)),
        shape: None,
    }
    .build()?;
    capture_transfer(&result.inputs, CaptureKind::ZoneAuthority)
}

fn capture_zone_mixed() -> Result<String> {
    let p256_owner = zone_keypair(true)?;
    let eddsa_owner = zone_keypair(false)?;
    let mut inputs = zone_proof_inputs(&p256_owner, 2, 2);
    inputs.input_utxos[1] = zone_real_input(&eddsa_owner, 1);
    let p256 = zone_p256_owner(&p256_owner, &mut inputs);
    let proofs = zone_spend_proofs(&inputs)?;
    let spends = attach_input_proofs(inputs.input_utxos.clone(), &proofs)?;
    let result = ZoneTransferP256Prover {
        inputs: spends,
        outputs: inputs.output_utxos.clone(),
        external_data: inputs.external_data.clone(),
        public_amounts: zone_amounts(&inputs)?,
        payer_pubkey_hash: inputs.payer_pubkey_hash,
        p256_owner: p256,
        zone_program_id: Some(Address::new_from_array(ZONE_PROGRAM)),
        shape: None,
    }
    .build()?;
    capture_transfer_p256(&result.inputs, CaptureKind::ZoneP256)
}

fn capture_merge(zone: bool) -> Result<String> {
    let result = if zone {
        build_merge_zone()?
    } else {
        build_merge()?
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let body = read_http_body(&mut stream).map_err(|error| error.to_string())?;
        sender.send(body).map_err(|error| error.to_string())?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let client = ProverClient::new(format!("http://{address}"));
    let _ = if zone {
        client.prove_merge_zone(&result.inputs)
    } else {
        client.prove_merge(&result.inputs)
    };
    let body = receiver.recv()?;
    match server.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => bail!("{error}"),
        Err(_) => bail!("merge capture server panicked"),
    }
    Ok(String::from_utf8(body)?)
}

fn capture_address_append() -> Result<String> {
    let inputs = BatchAddressAppendInputs {
        public_input_hash: BigUint::from(1u8),
        old_root: BigUint::from(2u8),
        new_root: BigUint::from(3u8),
        hashchain_hash: BigUint::from(4u8),
        start_index: 5,
        low_element_values: vec![BigUint::from(6u8)],
        low_element_indices: vec![BigUint::from(8u8)],
        low_element_next_values: vec![BigUint::from(10u8)],
        new_element_values: vec![BigUint::from(12u8)],
        low_element_proofs: vec![vec![BigUint::from(14u8)]],
        new_element_proofs: vec![vec![BigUint::from(18u8)]],
        tree_height: 40,
        batch_size: 1,
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let body = read_http_body(&mut stream).map_err(|error| error.to_string())?;
        sender.send(body).map_err(|error| error.to_string())?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let client = ProverClient::new(format!("http://{address}"));
    let _ = client.prove_batch_address_append(&inputs);
    let body = receiver.recv()?;
    match server.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => bail!("{error}"),
        Err(_) => bail!("address-append capture server panicked"),
    }
    Ok(String::from_utf8(body)?)
}

enum CaptureKind {
    Confidential,
    Zone,
    ZoneP256,
    ZoneAuthority,
}

fn capture_prover_inputs(inputs: &ProverInputs) -> Result<String> {
    match inputs {
        ProverInputs::Eddsa(value) => capture_transfer(value, CaptureKind::Confidential),
        ProverInputs::P256(value) => capture_transfer_p256(value, CaptureKind::Confidential),
    }
}

fn capture_transfer(inputs: &TransferInputs, kind: CaptureKind) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let body = read_http_body(&mut stream).map_err(|error| error.to_string())?;
        sender.send(body).map_err(|error| error.to_string())?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let client = ProverClient::new(format!("http://{address}"));
    match kind {
        CaptureKind::Confidential => {
            let _ = client.prove_transfer(inputs);
        }
        CaptureKind::Zone => {
            let _ = client.prove_transfer_zone(inputs);
        }
        CaptureKind::ZoneAuthority => {
            let _ = client.prove_zone_authority(inputs);
        }
        CaptureKind::ZoneP256 => bail!("p256 kind requires TransferP256Inputs"),
    }
    let body = receiver.recv()?;
    match server.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => bail!("{error}"),
        Err(_) => bail!("transfer capture server panicked"),
    }
    Ok(String::from_utf8(body)?)
}

fn capture_transfer_p256(inputs: &TransferP256Inputs, kind: CaptureKind) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let body = read_http_body(&mut stream).map_err(|error| error.to_string())?;
        sender.send(body).map_err(|error| error.to_string())?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let client = ProverClient::new(format!("http://{address}"));
    match kind {
        CaptureKind::Confidential => {
            let _ = client.prove_transfer_p256(inputs);
        }
        CaptureKind::ZoneP256 => {
            let _ = client.prove_transfer_p256_zone(inputs);
        }
        CaptureKind::Zone | CaptureKind::ZoneAuthority => {
            bail!("unexpected p256 capture kind")
        }
    }
    let body = receiver.recv()?;
    match server.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => bail!("{error}"),
        Err(_) => bail!("p256 capture server panicked"),
    }
    Ok(String::from_utf8(body)?)
}

fn read_http_body(stream: &mut impl Read) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut buffer)?;
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec())?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then_some(value)
        })
        .ok_or("missing content-length")?
        .trim()
        .parse::<usize>()?;
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes[header_end..header_end + content_length].to_vec())
}

fn confidential_inputs(
    p256: bool,
    n_inputs: usize,
    n_outputs: usize,
) -> Result<(SppProofInputs, Vec<SpendProof>)> {
    let keypair = confidential_keypair(p256)?;
    let mut inputs = vec![confidential_real_input(&keypair)];
    for position in 1..n_inputs {
        inputs.push(SppProofInputUtxo {
            utxo: Utxo {
                owner: PublicKey::zeroed(),
                asset: SOL_MINT,
                amount: 0,
                blinding: derive_blinding(&BLINDING_SEED, position as u8),
                zone_program_id: None,
                data: Data::default(),
            },
            nullifier_key: NullifierKey::from_secret([0; 31]),
            data_hash: None,
            zone_data_hash: None,
        });
    }
    // Owner tags for padding outputs use the blinding position (64+i), matching
    // public-input-assembly / buildProofInputs. Using the loop index alone
    // desynchronizes the mixed-owner request from the P1 public-input fixture.
    let mut outputs = Vec::with_capacity(n_outputs);
    for position in 0..n_outputs {
        let tag_position = position as u8 + 64;
        outputs.push(if position == 0 {
            SppProofOutputUtxo {
                owner_address: Some(keypair.shielded_address()?),
                owner_tag: Some(keypair.signing_pubkey().confidential_view_tag()?),
                asset: SOL_MINT,
                amount: 100,
                blinding: derive_blinding(&BLINDING_SEED, tag_position),
                ..Default::default()
            }
        } else {
            SppProofOutputUtxo {
                blinding: derive_blinding(&BLINDING_SEED, tag_position),
                owner_tag: Some([tag_position; 32]),
                ..Default::default()
            }
        });
    }
    let resolved_tags = outputs
        .iter()
        .map(|output| output.owner_tag.expect("fixture owner tag"))
        .collect::<Vec<_>>();
    let wire_outputs = outputs
        .iter()
        .zip(&resolved_tags)
        .map(|(output, tag)| {
            Ok::<_, anyhow::Error>(TransactOutput {
                utxo_hash: output.hash()?,
                owner_tag: OwnerTag::Inline(*tag),
                data: Some(vec![1, 2, 3]),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let external = ExternalData::new([41; 33], [42; 16], wire_outputs, resolved_tags, vec![])
        .with_public_sol(-5, Address::new_from_array([43; 32]))?;
    let mut inputs =
        SppProofInputs::new(inputs, outputs, external, Address::new_from_array([44; 32]));
    if p256 {
        inputs.sign_p256(&keypair)?;
    }
    let contexts = inputs.input_utxo_hashes()?;
    let tree = Address::new_from_array([45; 32]);
    let proofs = contexts
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(46 + index as u8); 32],
                leaf_index: index as u64,
                root: field_byte(47),
                root_seq: 48,
                root_index: 49 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(50 + index as u8); 40],
                low_element: field_byte(51),
                low_element_index: 0,
                high_element: field_byte(52),
                high_element_index: 1,
                root: field_byte(53),
                root_seq: 54,
                root_index: 55 + index as u16,
            },
        })
        .collect();
    Ok((inputs, proofs))
}

fn confidential_keypair(p256: bool) -> Result<ShieldedKeypair> {
    let signing = if p256 {
        SigningKey::from_bytes(&P256_SECRET)?
    } else {
        SigningKey::from_ed25519(&ED25519_SECRET)
    };
    Ok(ShieldedKeypair::from_keys(
        signing,
        ViewingKey::from_seed(&VIEWING_SEED, u32::from(p256))?,
    )?)
}

fn confidential_real_input(keypair: &ShieldedKeypair) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: 100,
            blinding: derive_blinding(&BLINDING_SEED, 0),
            zone_program_id: None,
            data: Data::default(),
        },
        keypair,
    )
}

fn zone_keypair(p256: bool) -> Result<ShieldedKeypair> {
    let signing = if p256 {
        SigningKey::from_bytes(&P256_SECRET)?
    } else {
        SigningKey::from_ed25519(&ZONE_ED25519_SECRET)
    };
    Ok(ShieldedKeypair::from_keys(
        signing,
        ViewingKey::from_seed(&ZONE_VIEWING_SEED, u32::from(p256))?,
    )?)
}

fn zone_real_input(keypair: &ShieldedKeypair, position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: ZONE_INPUT_AMOUNT,
            blinding: derive_blinding(&ZONE_BLINDING_SEED, position),
            zone_program_id: Some(Address::new_from_array(ZONE_PROGRAM)),
            data: Data::default(),
        },
        keypair,
    )
}

fn zone_proof_inputs(
    keypair: &ShieldedKeypair,
    n_inputs: usize,
    n_outputs: usize,
) -> SppProofInputs {
    let real = if n_inputs >= 2 { 2 } else { 1 };
    let input_utxos = (0..n_inputs)
        .map(|index| {
            if index < real {
                zone_real_input(keypair, index as u8)
            } else {
                SppProofInputUtxo {
                    utxo: Utxo {
                        owner: PublicKey::zeroed(),
                        asset: SOL_MINT,
                        amount: 0,
                        blinding: derive_blinding(&ZONE_BLINDING_SEED, index as u8),
                        zone_program_id: None,
                        data: Data::default(),
                    },
                    nullifier_key: NullifierKey::from_secret([0; 31]),
                    data_hash: None,
                    zone_data_hash: None,
                }
            }
        })
        .collect::<Vec<_>>();
    let total = ZONE_INPUT_AMOUNT * real as u64;
    let output_utxos = (0..n_outputs)
        .map(|index| {
            if index == 0 {
                SppProofOutputUtxo {
                    owner_address: None,
                    owner_tag: Some(field_byte(32 + index as u8)),
                    asset: SOL_MINT,
                    amount: total,
                    blinding: derive_blinding(&ZONE_BLINDING_SEED, 32 + index as u8),
                    zone_program_id: Some(Address::new_from_array(ZONE_PROGRAM)),
                    ..Default::default()
                }
            } else {
                SppProofOutputUtxo {
                    blinding: derive_blinding(&ZONE_BLINDING_SEED, 32 + index as u8),
                    owner_tag: Some(field_byte(32 + index as u8)),
                    zone_program_id: Some(Address::new_from_array(ZONE_PROGRAM)),
                    ..Default::default()
                }
            }
        })
        .collect::<Vec<_>>();
    let tags = output_utxos
        .iter()
        .map(|output| output.owner_tag.expect("zone output tag"))
        .collect::<Vec<_>>();
    let wire = output_utxos
        .iter()
        .zip(&tags)
        .map(|(output, tag)| TransactOutput {
            utxo_hash: output.hash().expect("output hash"),
            owner_tag: OwnerTag::Inline(*tag),
            data: Some(vec![1, 2, 3]),
        })
        .collect::<Vec<_>>();
    let external = ExternalData::new([71; 33], [72; 16], wire, tags, vec![])
        .with_public_sol(-5, Address::new_from_array(ZONE_USER_SOL))
        .expect("public sol leg");
    SppProofInputs::new(
        input_utxos,
        output_utxos,
        external,
        Address::new_from_array(ZONE_PAYER),
    )
}

fn zone_spend_proofs(inputs: &SppProofInputs) -> Result<Vec<SpendProof>> {
    let tree = Address::new_from_array(ZONE_TREE);
    Ok(inputs
        .input_utxo_hashes()?
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![field_byte(73 + index as u8); 32],
                leaf_index: index as u64,
                root: field_byte(74 + index as u8),
                root_seq: 75,
                root_index: 76 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 2, tree },
                path: vec![field_byte(77 + index as u8); 40],
                low_element: field_byte(78),
                low_element_index: index as u64,
                high_element: field_byte(79),
                high_element_index: index as u64 + 1,
                root: field_byte(80 + index as u8),
                root_seq: 81,
                root_index: 82 + index as u16,
            },
        })
        .collect())
}

fn zone_amounts(inputs: &SppProofInputs) -> Result<PublicAmounts> {
    let value = inputs.public_amounts()?;
    Ok(PublicAmounts {
        sol: value.sol,
        spl: value.spl,
        asset: value.asset,
    })
}

fn zone_p256_owner(keypair: &ShieldedKeypair, inputs: &mut SppProofInputs) -> P256Owner {
    inputs.sign_p256(keypair).expect("p256 signature");
    let signature = inputs.p256_signature.expect("p256 signature bytes");
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&signature[..32]);
    sig_s.copy_from_slice(&signature[32..]);
    P256Owner {
        pubkey: keypair.signing_pubkey().as_p256().expect("p256 pubkey"),
        sig_r,
        sig_s,
    }
}

fn build_merge() -> Result<zolana_client::MergeProofResult> {
    let keypair = merge_keypair();
    let prepared = PreparedMerge {
        inputs: merge_inputs(&keypair, None),
        output: merge_output(&keypair, None),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: SecretKey::from_slice(&MERGE_TX_VIEWING_SECRET).expect("tx viewing scalar"),
    };
    let contexts = prepared.input_utxo_hashes()?;
    MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key: keypair.nullifier_key.clone(),
        proofs: merge_spend_proofs(&contexts),
    })?
    .build()
    .map_err(Into::into)
}

fn build_merge_zone() -> Result<zolana_client::MergeProofResult> {
    let keypair = merge_keypair();
    let zone = Address::new_from_array(MERGE_ZONE_PROGRAM);
    let prepared = PreparedMergeZone {
        inputs: merge_inputs(&keypair, Some(zone)),
        output: merge_output(&keypair, Some(zone)),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: SecretKey::from_slice(&MERGE_TX_VIEWING_SECRET).expect("tx viewing scalar"),
        zone_program_id: zone,
    };
    let contexts = prepared.input_utxo_hashes()?;
    MergeZoneProver::try_from(MergeZoneWitness {
        prepared,
        nullifier_key: keypair.nullifier_key.clone(),
        proofs: merge_spend_proofs(&contexts),
    })?
    .build()
    .map_err(Into::into)
}

fn merge_keypair() -> ShieldedKeypair {
    ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&MERGE_SIGNING_SECRET).expect("p256 signing key"),
        ViewingKey::from_seed(&MERGE_VIEWING_SEED, 0).expect("viewing key"),
    )
    .expect("shielded keypair")
}

fn merge_inputs(keypair: &ShieldedKeypair, zone: Option<Address>) -> Vec<SppProofInputUtxo> {
    let mut inputs = MERGE_REAL_AMOUNTS
        .iter()
        .enumerate()
        .map(|(position, amount)| {
            SppProofInputUtxo::new(
                Utxo {
                    owner: keypair.signing_pubkey(),
                    asset: SOL_MINT,
                    amount: *amount,
                    blinding: derive_blinding(&MERGE_BLINDING_SEED, position as u8),
                    zone_program_id: zone,
                    data: Data::default(),
                },
                keypair,
            )
        })
        .collect::<Vec<_>>();
    while inputs.len() < MERGE_INPUTS {
        let position = inputs.len() as u8;
        inputs.push(SppProofInputUtxo {
            utxo: Utxo {
                owner: PublicKey::zeroed(),
                asset: SOL_MINT,
                amount: 0,
                blinding: derive_blinding(&MERGE_BLINDING_SEED, position),
                zone_program_id: None,
                data: Data::default(),
            },
            nullifier_key: NullifierKey::from_secret([0; 31]),
            data_hash: None,
            zone_data_hash: None,
        });
    }
    inputs
}

fn merge_output(keypair: &ShieldedKeypair, zone: Option<Address>) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        asset: SOL_MINT,
        amount: MERGE_OUTPUT_AMOUNT,
        blinding: derive_blinding(&MERGE_BLINDING_SEED, 2),
        owner_address: Some(keypair.shielded_address().expect("address")),
        zone_program_id: zone,
        ..Default::default()
    }
}

fn merge_spend_proofs(contexts: &[InputUtxoContext]) -> Vec<SpendProof> {
    let tree = Address::from_str(MERGE_TREE).expect("tree");
    contexts
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![[0u8; 32]; 32],
                leaf_index: index as u64,
                root: {
                    let mut root = [0u8; 32];
                    root[31] = 20 + index as u8;
                    root
                },
                root_seq: 1,
                root_index: 40 + index as u16,
            },
            nullifier: NonInclusionProof {
                leaf: context.nullifier,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![[0u8; 32]; 40],
                low_element: [0u8; 32],
                low_element_index: index as u64,
                high_element: [1u8; 32],
                high_element_index: (index + 1) as u64,
                root: {
                    let mut root = [0u8; 32];
                    root[31] = 30 + index as u8;
                    root
                },
                root_seq: 1,
                root_index: 50 + index as u16,
            },
        })
        .collect()
}

fn field_byte(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .context("xtask crate has no parent")
}
