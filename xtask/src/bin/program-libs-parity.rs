//! Generates the parity vectors for the four `program-libs` crates the review
//! queue never reached: `event`, `hasher` (everything but Poseidon, which
//! `poseidon-parity` already owns), `indexed-array`, and
//! `user-registry-interface`.
//!
//! Each section is a Rust oracle for a TypeScript reimplementation that had
//! nothing checking it. The values come from the real crates rather than from a
//! transcription of them, so a TypeScript test that reproduces a section is
//! comparing against the code the program compiles.
//!
//! ```text
//! cargo run -p xtask --bin program-libs-parity            # write the fixture
//! cargo run -p xtask --bin program-libs-parity -- --check  # fail on any drift
//! ```

use std::{collections::BTreeMap, env, fs, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use serde_json::{json, Map, Value};
use zolana_event::{
    output_data::MessageData,
    output_utxo::OutputUtxo,
    proofless::{
        encode_output_data, encode_verifiably_encrypted, OutputDataEncoding, ProoflessOutput,
    },
    tag::{self, InstructionTag},
};
use zolana_hasher::{
    bigint::{bigint_to_be_bytes_array, bigint_to_le_bytes_array},
    hash_chain::{create_hash_chain_from_slice, create_two_inputs_hash_chain},
    sha256::Sha256BE,
    zero_bytes, Hasher, HasherError, Keccak, Poseidon, Sha256, HASH_BYTES,
};
use zolana_indexed_array::{
    array::{IndexedArray, IndexedElement},
    errors::IndexedArrayError,
    HIGHEST_ADDRESS_PLUS_ONE,
};
use zolana_user_registry_interface::{
    instruction::{
        discriminator, RegisterData, RotateSyncDelegateKeyData, SetMergingEnabledData,
        SetSyncDelegateData, UpdateKeysData,
    },
    state::{NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN},
    user_record_pda, SyncDelegateEntry, UserRecord, USER_RECORD_SEED, USER_REGISTRY_PROGRAM_ID,
};

const FIXTURE: &str = "sdk-libs/ts/vectors/program-libs-parity-v1.json";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("program-libs-parity failed: {error:#}");
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
                    "Generate the Rust-side program-libs parity vectors.\n\nusage: cargo run -p xtask --bin program-libs-parity -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    let path = workspace_root()?.join(FIXTURE);
    let fixture = fixture()?;
    let mut bytes = serde_json::to_vec_pretty(&canonicalize(&fixture))?;
    bytes.push(b'\n');

    if check {
        let current = fs::read(&path)
            .with_context(|| format!("{FIXTURE} is missing; run the generator without --check"))?;
        if current != bytes {
            bail!("{FIXTURE} differs from the Rust program libraries; regenerate it");
        }
        println!("verified {FIXTURE}");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    println!("wrote {FIXTURE}");
    Ok(())
}

fn fixture() -> Result<Value> {
    Ok(json!({
        "event": {
            "outputData": output_data()?,
            "outputUtxo": output_utxo()?,
            "proofless": proofless()?,
            "tag": instruction_tags(),
        },
        "generatorCommand": "cargo run -p xtask --bin program-libs-parity",
        "hasher": {
            "bigint": bigint()?,
            "errors": hasher_errors(),
            "hashChain": hash_chain()?,
            "keccak": keccak()?,
            "sha256": sha256_vectors()?,
            "trait": hasher_trait(),
            "zeroBytes": zero_byte_tables(),
        },
        "id": "program-libs-parity",
        "indexedArray": indexed_array()?,
        "responsibility": concat!(
            "Rust oracle for the four program-libs crates the review queue never ",
            "admitted: zolana-event instruction tags and output encodings, the ",
            "non-Poseidon zolana-hasher surface, zolana-indexed-array, and ",
            "zolana-user-registry-interface. Poseidon itself is owned by ",
            "poseidon-parity-v1.json."
        ),
        "schema": "zolana-ts-fixtures-v1",
        "userRegistry": user_registry()?,
        "version": "1"
    }))
}

// ---------------------------------------------------------------- event/tag.rs

/// The eighteen dispatch tags plus the full `TryFrom<u8>` accept set, so a port
/// is pinned on which bytes the program refuses as well as which it takes.
fn instruction_tags() -> Value {
    let named: Vec<(&str, u8)> = vec![
        ("transact", tag::TRANSACT),
        ("deposit", tag::DEPOSIT),
        ("zoneTransact", tag::ZONE_TRANSACT),
        ("zoneAuthorityTransact", tag::ZONE_AUTHORITY_TRANSACT),
        ("createSplInterface", tag::CREATE_SPL_INTERFACE),
        ("createTree", tag::CREATE_TREE),
        ("createProtocolConfig", tag::CREATE_PROTOCOL_CONFIG),
        ("updateProtocolConfig", tag::UPDATE_PROTOCOL_CONFIG),
        ("pauseTree", tag::PAUSE_TREE),
        ("createZoneConfig", tag::CREATE_ZONE_CONFIG),
        ("updateZoneConfigOwner", tag::UPDATE_ZONE_CONFIG_OWNER),
        ("updateZoneConfig", tag::UPDATE_ZONE_CONFIG),
        ("mergeTransact", tag::MERGE_TRANSACT),
        ("zoneMergeTransact", tag::ZONE_MERGE_TRANSACT),
        ("emitEvent", tag::EMIT_EVENT),
        ("zoneDeposit", tag::ZONE_DEPOSIT),
        ("createAssetCounter", tag::CREATE_ASSET_COUNTER),
        ("batchUpdateNullifierTree", tag::BATCH_UPDATE_NULLIFIER_TREE),
    ];

    let values: Map<String, Value> = named
        .iter()
        .map(|(name, value)| ((*name).to_string(), json!(value)))
        .collect();

    let accepted: Vec<u8> = (0u8..=255)
        .filter(|byte| InstructionTag::try_from(*byte).is_ok())
        .collect();
    let rejected: Vec<u8> = (0u8..=255)
        .filter(|byte| InstructionTag::try_from(*byte).is_err())
        .collect();

    json!({
        "acceptedBytes": accepted,
        "count": named.len(),
        "rejectedSample": rejected.iter().copied().take(24).collect::<Vec<_>>(),
        "rejectedCount": rejected.len(),
        "rustPath": "program-libs/event/src/tag.rs",
        "values": values,
    })
}

// -------------------------------------------------- event/output_data.rs

/// `MessageData` carries a `FixIntLen<u16>` length prefix on `data` under
/// wincode and a borsh `u32` prefix under borsh. Both encodings ship so a port
/// cannot pass by matching the wrong one.
fn output_data() -> Result<Value> {
    let cases = vec![
        (
            "empty-data",
            MessageData {
                view_tag: fill(0x11),
                data: Vec::new(),
            },
        ),
        (
            "short-data",
            MessageData {
                view_tag: fill(0x22),
                data: vec![1, 2, 3, 4, 5],
            },
        ),
        (
            "zero-view-tag",
            MessageData {
                view_tag: [0u8; 32],
                data: vec![0xff; 7],
            },
        ),
        (
            "long-data-300",
            MessageData {
                view_tag: fill(0xab),
                data: (0..300u32).map(|i| (i % 251) as u8).collect(),
            },
        ),
        (
            "boundary-255",
            MessageData {
                view_tag: fill(0x01),
                data: vec![0x5a; 255],
            },
        ),
        (
            "boundary-256",
            MessageData {
                view_tag: fill(0x02),
                data: vec![0x5b; 256],
            },
        ),
    ];

    let mut vectors = Vec::new();
    for (name, value) in cases {
        vectors.push(json!({
            "borsh": hex(&borsh::to_vec(&value)?),
            "dataLen": value.data.len(),
            "name": name,
            "value": {
                "data": hex(&value.data),
                "viewTag": hex(&value.view_tag),
            },
            "wincode": hex(&wincode::serialize(&value)?),
        }));
    }

    Ok(json!({
        "lengthPrefix": { "borsh": "u32", "wincode": "u16" },
        "rustPath": "program-libs/event/src/output_data.rs",
        "rustSymbol": "MessageData",
        "vectors": vectors,
    }))
}

// -------------------------------------------------- event/output_utxo.rs

fn output_utxo() -> Result<Value> {
    let cases = vec![
        (
            "empty-data",
            OutputUtxo {
                view_tag: fill(0x33),
                utxo_hash: fill(0x44),
                data: Vec::new(),
            },
        ),
        (
            "short-data",
            OutputUtxo {
                view_tag: fill(0x55),
                utxo_hash: fill(0x66),
                data: vec![9, 8, 7],
            },
        ),
        (
            "zeroed",
            OutputUtxo {
                view_tag: [0u8; 32],
                utxo_hash: [0u8; 32],
                data: vec![0],
            },
        ),
        (
            "long-data-600",
            OutputUtxo {
                view_tag: fill(0x77),
                utxo_hash: fill(0x88),
                data: (0..600u32).map(|i| (i % 253) as u8).collect(),
            },
        ),
    ];

    let mut vectors = Vec::new();
    for (name, value) in cases {
        vectors.push(json!({
            "borsh": hex(&borsh::to_vec(&value)?),
            "dataLen": value.data.len(),
            "name": name,
            "value": {
                "data": hex(&value.data),
                "utxoHash": hex(&value.utxo_hash),
                "viewTag": hex(&value.view_tag),
            },
            "wincode": hex(&wincode::serialize(&value)?),
        }));
    }

    Ok(json!({
        "lengthPrefix": { "borsh": "u32", "wincode": "u16" },
        "rustPath": "program-libs/event/src/output_utxo.rs",
        "rustSymbol": "OutputUtxo",
        "vectors": vectors,
    }))
}

// ---------------------------------------------------- event/proofless.rs

/// `ProoflessOutput` is six borsh `Option`s in a fixed order after four fixed
/// fields, so the combinations that matter are the ones where a reader could
/// slide: every option absent, every option present, and each option present
/// alone.
fn proofless() -> Result<Value> {
    let base = ProoflessOutput {
        owner: fill(0xa1),
        blinding: fill31(0xb2),
        asset: fill(0xc3),
        amount: 1_234_567_890_123_456_789,
        data_hash: None,
        utxo_data: None,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: None,
    };

    let mut cases: Vec<(&str, ProoflessOutput)> = vec![("all-none", base.clone())];

    let all_some = ProoflessOutput {
        data_hash: Some(fill(0xd4)),
        utxo_data: Some(vec![1, 2, 3, 4]),
        zone_program_id: Some(fill(0xe5)),
        zone_data_hash: Some(fill(0xf6)),
        zone_data: Some(vec![9, 9, 9]),
        memo: Some(b"hello memo".to_vec()),
        ..base.clone()
    };
    cases.push(("all-some", all_some));

    cases.push((
        "data-hash-only",
        ProoflessOutput {
            data_hash: Some(fill(0x07)),
            ..base.clone()
        },
    ));
    cases.push((
        "utxo-data-only",
        ProoflessOutput {
            utxo_data: Some(vec![0xaa; 40]),
            ..base.clone()
        },
    ));
    cases.push((
        "zone-program-id-only",
        ProoflessOutput {
            zone_program_id: Some(fill(0x08)),
            ..base.clone()
        },
    ));
    cases.push((
        "zone-data-hash-only",
        ProoflessOutput {
            zone_data_hash: Some(fill(0x09)),
            ..base.clone()
        },
    ));
    cases.push((
        "zone-data-only",
        ProoflessOutput {
            zone_data: Some(vec![0xbb; 5]),
            ..base.clone()
        },
    ));
    cases.push((
        "memo-only",
        ProoflessOutput {
            memo: Some(b"memo".to_vec()),
            ..base.clone()
        },
    ));
    cases.push((
        "empty-vec-options",
        ProoflessOutput {
            utxo_data: Some(Vec::new()),
            zone_data: Some(Vec::new()),
            memo: Some(Vec::new()),
            ..base.clone()
        },
    ));
    cases.push((
        "zero-amount",
        ProoflessOutput {
            amount: 0,
            owner: [0u8; 32],
            blinding: [0u8; 31],
            asset: [0u8; 32],
            ..base.clone()
        },
    ));
    cases.push((
        "max-amount",
        ProoflessOutput {
            amount: u64::MAX,
            ..base.clone()
        },
    ));

    let mut vectors = Vec::new();
    for (name, value) in &cases {
        vectors.push(json!({
            "borsh": hex(&borsh::to_vec(value)?),
            "encodeOutputData": hex(&encode_output_data(value.clone())),
            "name": name,
            "value": proofless_json(value),
        }));
    }

    let encodings = vec![
        (
            "plaintext",
            OutputDataEncoding::PLAINTEXT_TAG,
            OutputDataEncoding::Plaintext(vec![1, 2, 3]),
        ),
        (
            "encrypted",
            OutputDataEncoding::ENCRYPTED_TAG,
            OutputDataEncoding::Encrypted(vec![4, 5]),
        ),
        (
            "verifiable",
            OutputDataEncoding::VERIFIABLY_ENCRYPTED_TAG,
            OutputDataEncoding::VerifiablyEncrypted(vec![6]),
        ),
    ];
    let mut encoding_vectors = Vec::new();
    for (name, tag_value, value) in encodings {
        encoding_vectors.push(json!({
            "borsh": hex(&borsh::to_vec(&value)?),
            "name": name,
            "tag": tag_value,
        }));
    }

    Ok(json!({
        "encodeOutputDataVersionByte": 0,
        "encodeVerifiablyEncrypted": {
            "empty": hex(&encode_verifiably_encrypted(Vec::new())),
            "sample": hex(&encode_verifiably_encrypted(vec![0xde, 0xad, 0xbe, 0xef])),
        },
        "fieldOrder": [
            "owner", "blinding", "asset", "amount", "dataHash", "utxoData",
            "zoneProgramId", "zoneDataHash", "zoneData", "memo"
        ],
        "outputDataEncoding": encoding_vectors,
        "rustPath": "program-libs/event/src/proofless.rs",
        "rustSymbol": "ProoflessOutput",
        "vectors": vectors,
    }))
}

fn proofless_json(value: &ProoflessOutput) -> Value {
    json!({
        "amount": value.amount.to_string(),
        "asset": hex(&value.asset),
        "blinding": hex(&value.blinding),
        "dataHash": value.data_hash.map(|hash| hex(&hash)),
        "memo": value.memo.as_ref().map(|data| hex(data)),
        "owner": hex(&value.owner),
        "utxoData": value.utxo_data.as_ref().map(|data| hex(data)),
        "zoneData": value.zone_data.as_ref().map(|data| hex(data)),
        "zoneDataHash": value.zone_data_hash.map(|hash| hex(&hash)),
        "zoneProgramId": value.zone_program_id.map(|id| hex(&id)),
    })
}

// ------------------------------------------------------- hasher/lib.rs

/// The `Hasher` trait's per-implementation `ID` discriminants and `HASH_BYTES`.
fn hasher_trait() -> Value {
    json!({
        "hashBytes": HASH_BYTES,
        "ids": {
            "keccak": <Keccak as Hasher>::ID,
            "poseidon": <Poseidon as Hasher>::ID,
            "sha256": <Sha256 as Hasher>::ID,
            "sha256Be": <Sha256BE as Hasher>::ID,
        },
        "rustPath": "program-libs/hasher/src/lib.rs",
        "rustSymbol": "Hasher",
    })
}

// ---------------------------------------------------- hasher/sha256.rs

/// `hashv` concatenates its inputs before digesting, so the multi-input vectors
/// are the ones that catch a port that hashes each slice separately.
fn sha256_vectors() -> Result<Value> {
    let inputs = digest_inputs();
    let mut vectors = Vec::new();
    for (name, parts) in &inputs {
        let refs: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();
        vectors.push(json!({
            "hashv": hex(&Sha256::hashv(&refs)?),
            "inputs": parts.iter().map(|part| hex(part)).collect::<Vec<_>>(),
            "name": name,
            "sha256Be": hex(&Sha256BE::hashv(&refs)?),
        }));
    }

    Ok(json!({
        "note": "Sha256BE is Sha256 with byte 0 forced to zero, for BN254 big-endian fit.",
        "rustPath": "program-libs/hasher/src/sha256.rs",
        "rustSymbol": "<Sha256 as Hasher>::hashv",
        "vectors": vectors,
    }))
}

fn keccak() -> Result<Value> {
    let inputs = digest_inputs();
    let mut vectors = Vec::new();
    for (name, parts) in &inputs {
        let refs: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();
        vectors.push(json!({
            "hashv": hex(&Keccak::hashv(&refs)?),
            "inputs": parts.iter().map(|part| hex(part)).collect::<Vec<_>>(),
            "name": name,
        }));
    }

    Ok(json!({
        "rustPath": "program-libs/hasher/src/keccak.rs",
        "rustSymbol": "<Keccak as Hasher>::hashv",
        "vectors": vectors,
    }))
}

/// Shared between the SHA-256 and Keccak sections: empty, single, two-part and
/// unequal-length inputs, plus the 32-byte pairs the Merkle trees actually use.
fn digest_inputs() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    vec![
        ("empty-single", vec![Vec::new()]),
        ("empty-two", vec![Vec::new(), Vec::new()]),
        ("one-byte", vec![vec![0x00]]),
        ("abc", vec![b"abc".to_vec()]),
        ("split-abc", vec![b"a".to_vec(), b"bc".to_vec()]),
        ("zeros-32", vec![vec![0u8; 32]]),
        ("pair-zero-zero", vec![vec![0u8; 32], vec![0u8; 32]]),
        (
            "pair-one-two",
            vec![fill(0x01).to_vec(), fill(0x02).to_vec()],
        ),
        (
            "pair-asymmetric",
            vec![fill(0x02).to_vec(), fill(0x01).to_vec()],
        ),
        (
            "three-parts",
            vec![
                fill(0xaa).to_vec(),
                fill(0xbb).to_vec(),
                fill(0xcc).to_vec(),
            ],
        ),
        (
            "uneven",
            vec![vec![0xde, 0xad], vec![0xbe, 0xef, 0x00], vec![0xff]],
        ),
        (
            "long-1000",
            vec![(0..1000u32).map(|i| (i % 256) as u8).collect()],
        ),
        ("ff-32", vec![vec![0xffu8; 32]]),
    ]
}

// ---------------------------------------------------- hasher/bigint.rs

/// Both directions plus the length rejection, which is the only behaviour in
/// this file a port can get wrong silently.
fn bigint() -> Result<Value> {
    let values: Vec<(&str, BigUint)> =
        vec![
        ("zero", BigUint::from(0u8)),
        ("one", BigUint::from(1u8)),
        ("255", BigUint::from(255u8)),
        ("256", BigUint::from(256u16)),
        ("u64-max", BigUint::from(u64::MAX)),
        (
            "bn254-modulus-minus-one",
            BigUint::parse_bytes(
                b"21888242871839275222246405745257275088548364400416034343698204186575808495616",
                10,
            )
            .context("modulus literal")?,
        ),
        (
            "highest-address-plus-one",
            BigUint::parse_bytes(HIGHEST_ADDRESS_PLUS_ONE.as_bytes(), 10)
                .context("highest address literal")?,
        ),
        ("max-32-bytes", (BigUint::from(1u8) << 256u32) - BigUint::from(1u8)),
    ];

    let mut vectors = Vec::new();
    for (name, value) in &values {
        vectors.push(json!({
            "be32": hex(&bigint_to_be_bytes_array::<32>(value)?),
            "decimal": value.to_string(),
            "le32": hex(&bigint_to_le_bytes_array::<32>(value)?),
            "name": name,
        }));
    }

    // 2^256 needs 33 bytes and must be refused at width 32.
    let too_wide = BigUint::from(1u8) << 256u32;
    let be_error = bigint_to_be_bytes_array::<32>(&too_wide)
        .err()
        .context("2^256 must not fit in 32 bytes")?;
    let le_error = bigint_to_le_bytes_array::<32>(&too_wide)
        .err()
        .context("2^256 must not fit in 32 bytes")?;

    Ok(json!({
        "rejects": [{
            "beError": be_error.to_string(),
            "decimal": too_wide.to_string(),
            "leError": le_error.to_string(),
            "name": "two-pow-256-into-32",
            "width": 32,
        }],
        "rustPath": "program-libs/hasher/src/bigint.rs",
        "rustSymbol": "bigint_to_be_bytes_array",
        "vectors": vectors,
    }))
}

// ------------------------------------------------- hasher/hash_chain.rs

/// The empty case returns all zeros rather than erroring, and the one-element
/// case returns the element unhashed. Both are easy to get wrong.
fn hash_chain() -> Result<Value> {
    let element = |byte: u8| -> [u8; 32] { fill(byte) };
    let single: Vec<[u8; 32]> = vec![element(0x01)];
    let pair: Vec<[u8; 32]> = vec![element(0x01), element(0x02)];
    let triple: Vec<[u8; 32]> = vec![element(0x01), element(0x02), element(0x03)];
    let reversed: Vec<[u8; 32]> = vec![element(0x02), element(0x01)];
    let zeros: Vec<[u8; 32]> = vec![[0u8; 32], [0u8; 32], [0u8; 32]];
    let eight: Vec<[u8; 32]> = (1u8..=8).map(element).collect();

    let cases: Vec<(&str, Vec<[u8; 32]>)> = vec![
        ("empty", Vec::new()),
        ("single", single),
        ("pair", pair),
        ("pair-reversed", reversed),
        ("triple", triple),
        ("zeros-three", zeros),
        ("eight", eight),
    ];

    let mut single_vectors = Vec::new();
    for (name, inputs) in &cases {
        single_vectors.push(json!({
            "inputs": inputs.iter().map(|input| hex(input)).collect::<Vec<_>>(),
            "name": name,
            "output": hex(&create_hash_chain_from_slice(inputs)?),
        }));
    }

    /// A named pair of equal-length hash columns.
    type PairedCase = (&'static str, Vec<[u8; 32]>, Vec<[u8; 32]>);

    let two_input_cases: Vec<PairedCase> = vec![
        ("empty", Vec::new(), Vec::new()),
        ("one-pair", vec![element(0x01)], vec![element(0x02)]),
        (
            "two-pairs",
            vec![element(0x01), element(0x03)],
            vec![element(0x02), element(0x04)],
        ),
        (
            "four-pairs",
            (1u8..=4).map(element).collect(),
            (5u8..=8).map(element).collect(),
        ),
    ];

    let mut two_input_vectors = Vec::new();
    for (name, first, second) in &two_input_cases {
        two_input_vectors.push(json!({
            "first": first.iter().map(|input| hex(input)).collect::<Vec<_>>(),
            "name": name,
            "output": hex(&create_two_inputs_hash_chain(first, second)?),
            "second": second.iter().map(|input| hex(input)).collect::<Vec<_>>(),
        }));
    }

    let mismatch = create_two_inputs_hash_chain(&[element(1)], &[])
        .err()
        .context("length mismatch must error")?;

    Ok(json!({
        "createHashChainFromSlice": single_vectors,
        "createTwoInputsHashChain": two_input_vectors,
        "emptyReturnsZero": true,
        "rustPath": "program-libs/hasher/src/hash_chain.rs",
        "twoInputsLengthMismatch": {
            "error": mismatch.to_string(),
            "code": u32::from(mismatch),
        },
    }))
}

// ---------------------------------------------------- hasher/errors.rs

/// `HasherError as u32` is the wire code a client sees through
/// `ProgramError::Custom`, so the mapping is a public contract.
fn hasher_errors() -> Value {
    let variants: Vec<(&str, HasherError)> = vec![
        ("IntegerOverflow", HasherError::IntegerOverflow),
        ("InvalidInputLength", HasherError::InvalidInputLength(0, 0)),
        ("InvalidNumFields", HasherError::InvalidNumFields),
        ("EmptyInput", HasherError::EmptyInput),
        ("BorshError", HasherError::BorshError),
        (
            "OptionHashToFieldSizeZero",
            HasherError::OptionHashToFieldSizeZero,
        ),
        (
            "PoseidonFeatureNotEnabled",
            HasherError::PoseidonFeatureNotEnabled,
        ),
        (
            "Sha256FeatureNotEnabled",
            HasherError::Sha256FeatureNotEnabled,
        ),
        (
            "KeccakFeatureNotEnabled",
            HasherError::KeccakFeatureNotEnabled,
        ),
    ];

    let mut codes = Map::new();
    let mut messages = Map::new();
    for (name, variant) in variants {
        messages.insert(name.to_string(), json!(variant.to_string()));
        codes.insert(name.to_string(), json!(u32::from(variant)));
    }

    json!({
        "codes": codes,
        "messages": messages,
        "note": "Poseidon(_) is 7002 and PoseidonSyscall/UnknownSolanaSyscall carry their own values.",
        "rustPath": "program-libs/hasher/src/errors.rs",
        "rustSymbol": "HasherError",
    })
}

// ------------------------------------------------- hasher/zero_bytes/*

/// The committed zero-leaf tables. TypeScript builds its zero column at runtime
/// by hashing upward from a 32-byte zero leaf, so publishing the tables turns
/// "no TypeScript reads this file" into a checkable equivalence.
fn zero_byte_tables() -> Value {
    json!({
        "keccak": zero_bytes::keccak::ZERO_BYTES.iter().map(|row| hex(row)).collect::<Vec<_>>(),
        "maxHeight": zero_bytes::MAX_HEIGHT,
        "poseidon": zero_bytes::poseidon::ZERO_BYTES.iter().map(|row| hex(row)).collect::<Vec<_>>(),
        "rustPath": "program-libs/hasher/src/zero_bytes/",
        "sha256": zero_bytes::sha256::ZERO_BYTES.iter().map(|row| hex(row)).collect::<Vec<_>>(),
    })
}

// -------------------------------------------------------- indexed-array

/// A scripted append sequence with the element hash after every step, so a port
/// is pinned on the linked-list bookkeeping and not just the final root.
fn indexed_array() -> Result<Value> {
    let mut array: IndexedArray<Poseidon, usize> = IndexedArray::default();
    let appended = [30u32, 10, 20, 50, 40];

    let mut steps = Vec::new();
    for value in appended {
        let value = BigUint::from(value);
        let low_index = array.find_low_element_index_for_nonexistent(&value)?;
        let bundle = array.append(&value)?;
        steps.push(json!({
            "append": value.to_string(),
            "elements": elements_json(&array)?,
            "highestElementIndex": array.highest_element_index,
            "lowElementIndex": low_index,
            "newElementIndex": bundle.new_element.index,
            "newElementNextValue": bundle.new_element_next_value.to_string(),
            "newLowElementNextIndex": bundle.new_low_element.next_index,
        }));
    }

    // Element hashes over both hashers the SDK can pick.
    let mut hashes = Vec::new();
    for index in 0..=array.len() {
        hashes.push(json!({
            "index": index,
            "poseidon": hex(&array.hash_element(index)?),
        }));
    }

    let standalone = IndexedElement::<usize> {
        index: 3,
        value: BigUint::from(42u8),
        next_index: 7,
    };
    let standalone_hash = standalone.hash::<Poseidon>(&BigUint::from(99u8))?;

    let rejects = vec![
        reject(
            "append-duplicate",
            array.clone().append(&BigUint::from(30u8)).err(),
        ),
        reject(
            "low-element-too-high",
            array
                .clone()
                .append_with_low_element_index(3, &BigUint::from(5u8))
                .err(),
        ),
        reject(
            "new-element-past-next",
            array
                .clone()
                .append_with_low_element_index(2, &BigUint::from(999u32))
                .err(),
        ),
        reject(
            "find-low-existing",
            array
                .find_low_element_index_for_nonexistent(&BigUint::from(10u8))
                .err(),
        ),
        reject(
            "find-low-for-absent-existent",
            array
                .find_low_element_index_for_existent(&BigUint::from(777u32))
                .err(),
        ),
    ];

    let (low_element, next_value) = array.find_low_element_for_nonexistent(&BigUint::from(35u8))?;

    Ok(json!({
        "defaultArray": {
            "currentNodeIndex": 0,
            "elements": [{ "index": 0, "nextIndex": 0, "value": "0" }],
            "highestValue": "0",
        },
        "errorVariants": indexed_array_error_variants(),
        "finalElements": elements_json(&array)?,
        "findLowElementForNonexistent": {
            "lowElementIndex": low_element.index,
            "lowElementValue": low_element.value.to_string(),
            "nextValue": next_value.to_string(),
            "query": "35",
        },
        "hashes": hashes,
        "highestAddressPlusOne": HIGHEST_ADDRESS_PLUS_ONE,
        "rejects": rejects,
        "rustPath": "program-libs/indexed-array/src/array.rs",
        "standaloneElementHash": {
            "index": standalone.index,
            "nextIndex": standalone.next_index,
            "nextValue": "99",
            "poseidon": hex(&standalone_hash),
            "value": "42",
        },
        "steps": steps,
    }))
}

fn elements_json(array: &IndexedArray<Poseidon, usize>) -> Result<Value> {
    let mut out = Vec::new();
    for index in 0..=array.len() {
        let element = array.get(index).context("element index in range")?;
        out.push(json!({
            "index": element.index,
            "nextIndex": element.next_index,
            "value": element.value.to_string(),
        }));
    }
    Ok(Value::Array(out))
}

fn reject(name: &str, error: Option<IndexedArrayError>) -> Value {
    json!({
        "error": error.as_ref().map(std::string::ToString::to_string),
        "name": name,
    })
}

fn indexed_array_error_variants() -> Value {
    let variants: Vec<IndexedArrayError> = vec![
        IndexedArrayError::IntegerOverflow,
        IndexedArrayError::IndexHigherThanMax,
        IndexedArrayError::LowElementNotFound,
        IndexedArrayError::LowElementGreaterOrEqualToNewElement,
        IndexedArrayError::NewElementGreaterOrEqualToNextElement,
        IndexedArrayError::ElementAlreadyExists,
        IndexedArrayError::ElementDoesNotExist,
        IndexedArrayError::ArrayFull,
    ];
    Value::Array(
        variants
            .into_iter()
            .map(|variant| json!(variant.to_string()))
            .collect(),
    )
}

// ------------------------------------------------------- user-registry

/// The program id, the PDA seed and derivations, the `UserRecord` borsh layout,
/// `space_for`, and the instruction discriminators with their payloads.
fn user_registry() -> Result<Value> {
    let owners: Vec<[u8; 32]> = vec![[0u8; 32], fill(0x01), fill(0xff), USER_REGISTRY_PROGRAM_ID];
    let mut pdas = Vec::new();
    for owner in &owners {
        let (pda, bump) = user_record_pda(&solana_pubkey::Pubkey::new_from_array(*owner));
        pdas.push(json!({
            "bump": bump,
            "owner": bs58::encode(owner).into_string(),
            "ownerHex": hex(owner),
            "pda": pda.to_string(),
        }));
    }

    let entry = |byte: u8, created_at: i64| SyncDelegateEntry {
        delegate: fill(byte),
        sync_pubkey: fill33(byte.wrapping_add(1)),
        viewing_pubkey: fill33(byte.wrapping_add(2)),
        created_at,
    };

    let minimal = UserRecord {
        owner: solana_pubkey::Pubkey::new_from_array(fill(0x11)),
        bump: 254,
        owner_p256: None,
        nullifier_pubkey: fill(0x22),
        viewing_pubkey: fill33(0x33),
        sync_delegate: None,
        entries: Vec::new(),
        merging_enabled: false,
    };

    let full = UserRecord {
        owner: solana_pubkey::Pubkey::new_from_array(fill(0x44)),
        bump: 255,
        owner_p256: Some(fill33(0x55)),
        nullifier_pubkey: fill(0x66),
        viewing_pubkey: fill33(0x77),
        sync_delegate: Some(fill(0x88)),
        entries: vec![entry(0x90, 1_700_000_000), entry(0xa0, -1)],
        merging_enabled: true,
    };

    let delegate_no_entries = UserRecord {
        sync_delegate: Some(fill(0xbb)),
        entries: Vec::new(),
        ..minimal.clone()
    };

    // Revocation clears `sync_delegate` and leaves historical `entries`. The
    // sender must encrypt to the owner key again; leftover entries must not win.
    let revoked_with_entries = UserRecord {
        sync_delegate: None,
        entries: vec![entry(0xc0, 1_700_000_001)],
        ..minimal.clone()
    };

    let records: Vec<(&str, UserRecord)> = vec![
        ("minimal", minimal.clone()),
        ("full", full.clone()),
        ("delegate-without-entries", delegate_no_entries.clone()),
        ("revoked-with-entries", revoked_with_entries.clone()),
    ];

    let mut record_vectors = Vec::new();
    for (name, record) in &records {
        let body = borsh::to_vec(record)?;
        let mut account = vec![UserRecord::DISCRIMINATOR];
        account.extend_from_slice(&body);
        // The round trip is the point: it proves the discriminator prefix is what
        // `try_from_account_data` strips, not an assumption about it.
        let decoded = UserRecord::try_from_account_data(&account)?;
        if &decoded != record {
            bail!("user record {name} did not round trip");
        }
        record_vectors.push(json!({
            "accountData": hex(&account),
            "borshBody": hex(&body),
            "entryCount": record.entries.len(),
            "name": name,
            "senderViewingPubkey": hex(&record.sender_viewing_pubkey()),
            "spaceFor": UserRecord::space_for(record.entries.len()),
            "value": user_record_json(record),
        }));
    }

    // Named cases for the fund-losing sync-delegate viewing-key rule (W07).
    // Each `expected` is `UserRecord::sender_viewing_pubkey()` on the named record.
    let sender_viewing_key_rule = json!({
        "cases": [
            {
                "name": "no-delegate",
                "record": "minimal",
                "uses": "owner",
                "expected": hex(&minimal.sender_viewing_pubkey()),
                "ownerViewingPubkey": hex(&minimal.viewing_pubkey),
            },
            {
                "name": "active-with-entries",
                "record": "full",
                "uses": "latest-entry",
                "expected": hex(&full.sender_viewing_pubkey()),
                "ownerViewingPubkey": hex(&full.viewing_pubkey),
                "latestEntryViewingPubkey": hex(
                    &full
                        .entries
                        .last()
                        .context("full record must carry entries")?
                        .viewing_pubkey,
                ),
            },
            {
                "name": "active-empty-entries",
                "record": "delegate-without-entries",
                "uses": "owner-fallback",
                "expected": hex(&delegate_no_entries.sender_viewing_pubkey()),
                "ownerViewingPubkey": hex(&delegate_no_entries.viewing_pubkey),
            },
            {
                "name": "revoked-with-entries",
                "record": "revoked-with-entries",
                "uses": "owner",
                "expected": hex(&revoked_with_entries.sender_viewing_pubkey()),
                "ownerViewingPubkey": hex(&revoked_with_entries.viewing_pubkey),
                "leftoverEntryViewingPubkey": hex(
                    &revoked_with_entries
                        .entries
                        .last()
                        .context("revoked record must retain entries")?
                        .viewing_pubkey,
                ),
            },
        ],
    });

    let bad_discriminator = UserRecord::try_from_account_data(&[9u8, 0, 0])
        .err()
        .context("a wrong discriminator must be refused")?;
    let empty_account = UserRecord::try_from_account_data(&[])
        .err()
        .context("empty account data must be refused")?;

    let register = RegisterData {
        owner_p256: Some(fill33(0x0a)),
        nullifier_pubkey: fill(0x0b),
        viewing_pubkey: fill33(0x0c),
    };
    let register_none = RegisterData {
        owner_p256: None,
        nullifier_pubkey: fill(0x0d),
        viewing_pubkey: fill33(0x0e),
    };
    let update_keys = UpdateKeysData {
        owner_p256: Some(fill33(0x1a)),
        nullifier_pubkey: fill(0x1b),
        viewing_pubkey: fill33(0x1c),
    };
    let set_sync = SetSyncDelegateData {
        sync_delegate: fill(0x2a),
        sync_pubkey: fill33(0x2b),
        viewing_pubkey: fill33(0x2c),
    };
    let rotate = RotateSyncDelegateKeyData {
        sync_pubkey: fill33(0x3a),
        viewing_pubkey: fill33(0x3b),
    };

    let payloads = json!({
        "register": hex(&borsh::to_vec(&register)?),
        "registerNoP256": hex(&borsh::to_vec(&register_none)?),
        "rotateSyncDelegateKey": hex(&borsh::to_vec(&rotate)?),
        "setMergingEnabledFalse": hex(&borsh::to_vec(&SetMergingEnabledData { enabled: false })?),
        "setMergingEnabledTrue": hex(&borsh::to_vec(&SetMergingEnabledData { enabled: true })?),
        "setSyncDelegate": hex(&borsh::to_vec(&set_sync)?),
        "updateKeys": hex(&borsh::to_vec(&update_keys)?),
    });

    Ok(json!({
        "constants": {
            "nullifierPubkeyLen": NULLIFIER_PUBKEY_LEN,
            "p256PubkeyLen": P256_PUBKEY_LEN,
            "programId": bs58::encode(USER_REGISTRY_PROGRAM_ID).into_string(),
            "programIdHex": hex(&USER_REGISTRY_PROGRAM_ID),
            "recordSeed": String::from_utf8(USER_RECORD_SEED.to_vec())?,
            "recordSeedHex": hex(USER_RECORD_SEED),
            "syncDelegateEntrySerializedLen": SyncDelegateEntry::SERIALIZED_LEN,
            "userRecordDiscriminator": UserRecord::DISCRIMINATOR,
        },
        "instruction": {
            "discriminators": {
                "register": discriminator::REGISTER,
                "revokeSyncDelegate": discriminator::REVOKE_SYNC_DELEGATE,
                "rotateSyncDelegateKey": discriminator::ROTATE_SYNC_DELEGATE_KEY,
                "setMergingEnabled": discriminator::SET_MERGING_ENABLED,
                "setSyncDelegate": discriminator::SET_SYNC_DELEGATE,
                "updateKeys": discriminator::UPDATE_KEYS,
            },
            "payloads": payloads,
            "rustPath": "program-libs/user-registry-interface/src/instruction.rs",
        },
        "pdas": pdas,
        "rejects": {
            "badDiscriminator": bad_discriminator.to_string(),
            "emptyAccount": empty_account.to_string(),
        },
        "rustPath": "program-libs/user-registry-interface/src/lib.rs",
        "spaceFor": (0..4usize)
            .map(|count| json!({ "entries": count, "space": UserRecord::space_for(count) }))
            .collect::<Vec<_>>(),
        "senderViewingKeyRule": sender_viewing_key_rule,
        "state": {
            "records": record_vectors,
            "rustPath": "program-libs/user-registry-interface/src/state.rs",
        },
    }))
}

fn user_record_json(record: &UserRecord) -> Value {
    json!({
        "bump": record.bump,
        "entries": record
            .entries
            .iter()
            .map(|entry| json!({
                "createdAt": entry.created_at.to_string(),
                "delegate": hex(&entry.delegate),
                "syncPubkey": hex(&entry.sync_pubkey),
                "viewingPubkey": hex(&entry.viewing_pubkey),
            }))
            .collect::<Vec<_>>(),
        "mergingEnabled": record.merging_enabled,
        "nullifierPubkey": hex(&record.nullifier_pubkey),
        "owner": record.owner.to_string(),
        "ownerHex": hex(record.owner.as_ref()),
        "ownerP256": record.owner_p256.map(|key| hex(&key)),
        "syncDelegate": record.sync_delegate.map(|key| hex(&key)),
        "viewingPubkey": hex(&record.viewing_pubkey),
    })
}

// ------------------------------------------------------------- helpers

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn fill31(byte: u8) -> [u8; 31] {
    [byte; 31]
}

fn fill33(byte: u8) -> [u8; 33] {
    [byte; 33]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has no parent directory")
}
