//! Records which indexer wire bodies Rust's `zolana-indexer-api` serde
//! contract refuses.
//!
//! `@zolana/indexer-api` already rejects malformed scalars and responses in
//! hand-written unit tests. Those prove TypeScript refuses something; they do
//! not prove it refuses the same bodies Rust refuses. This binary drives the
//! production `Deserialize` impls over a fixed matrix of malformed and
//! tampered payloads and records each accept/reject decision so the TypeScript
//! suite can replay the identical wires.
//!
//! ```text
//! cargo run -p xtask --bin indexer-schema-rejects            # write the fixture
//! cargo run -p xtask --bin indexer-schema-rejects -- --check # fail on any drift
//! ```

use std::{env, fs, path::PathBuf, process::ExitCode};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_indexer_api::{
    Base64String, GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest, GetMerkleProofsResponse,
    GetNonInclusionProofsRequest, GetNonInclusionProofsResponse, GetNullifierQueueElementsRequest,
    GetNullifierQueueElementsResponse, GetRingsByTagsRequest, GetShieldedTransactionsByTagsResponse,
    Hash, Limit, SerializablePubkey, SerializableSignature, PAGE_LIMIT,
};

const FIXTURE: &str = "sdk-libs/ts/vectors/indexer-schema-rejects-v1.json";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("indexer-schema-rejects failed: {error:#}");
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
                    "Generate indexer-api Rust rejection and tamper vectors.\n\nusage: cargo run -p xtask --bin indexer-schema-rejects -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    let path = workspace_root()?.join(FIXTURE);
    let fixture = canonicalize(&fixture()?);
    let mut bytes = serde_json::to_vec_pretty(&fixture)?;
    bytes.push(b'\n');

    if check {
        let current = fs::read(&path)
            .with_context(|| format!("{FIXTURE} is missing; run the generator without --check"))?;
        if current != bytes {
            bail!("{FIXTURE} differs from Rust indexer-api serde; regenerate it");
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
    let hash = Hash::from([1u8; 32]);
    let tree = SerializablePubkey::from(Pubkey::new_from_array([2u8; 32]));
    let signature = SerializableSignature::from(Signature::from([3u8; 64]));
    let hash_str = hash.to_string();
    let tree_str = tree.to_string();
    let signature_str = signature.to_string();

    let valid_merkle_response = json!({
        "context": { "block_time": 1234 },
        "proofs": [{
            "leaf": hash_str,
            "merkle_context": { "tree_type": 1, "tree": tree_str },
            "path": [hash_str],
            "leaf_index": 7,
            "root": hash_str,
            "root_seq": 8,
            "root_index": 9,
        }],
    });
    // Control: the base body must still deserialize, or the tampers are noise.
    let _: GetMerkleProofsResponse = serde_json::from_value(valid_merkle_response.clone())
        .context("valid merkle response must deserialize")?;

    let valid_rings_request = json!({
        "tags": [hash_str],
        "cursor": "AQID",
        "limit": 1,
    });
    let _: GetRingsByTagsRequest = serde_json::from_value(valid_rings_request.clone())
        .context("valid rings request must deserialize")?;

    let valid_encrypted = json!({
        "context": { "block_time": 0 },
        "matches": [{
            "slot": 0,
            "tx_signature": signature_str,
            "output_slot": {
                "view_tag": hash_str,
                "output_context": {
                    "hash": hash_str,
                    "tree": tree_str,
                    "leaf_index": 0,
                },
                "payload": "AA==",
            },
            "tx_viewing_pk": null,
            "salt": null,
        }],
        "next_cursor": null,
    });
    let _: GetEncryptedUtxosByTagsResponse = serde_json::from_value(valid_encrypted.clone())
        .context("valid encrypted response must deserialize")?;

    let valid_non_inclusion = json!({
        "context": { "block_time": 0 },
        "proofs": [{
            "leaf": hash_str,
            "merkle_context": { "tree_type": 0, "tree": tree_str },
            "path": [hash_str],
            "low_element": hash_str,
            "low_element_index": 2,
            "high_element": hash_str,
            "high_element_index": 3,
            "root": hash_str,
            "root_seq": 0,
            "root_index": 0,
        }],
    });
    let _: GetNonInclusionProofsResponse = serde_json::from_value(valid_non_inclusion.clone())
        .context("valid non-inclusion response must deserialize")?;

    let scalars = vec![
        probe_scalar::<Base64String>("invalid-base64", "base64", "base64String", json!("A===")),
        probe_scalar::<Hash>("hash-short", "hash", "hash", json!("short")),
        probe_scalar::<Hash>("hash-wrong-byte-length", "hash", "hash", {
            // 31 zero bytes, base58-encoded — WrongSize rather than Invalid.
            let encoded = bs58::encode([0u8; 31]).into_string();
            json!(encoded)
        }),
        probe_scalar::<Limit>("limit-zero", "limit", "limit", json!(0)),
        probe_scalar::<Limit>(
            "limit-above-page",
            "limit",
            "limit",
            json!(PAGE_LIMIT + 1),
        ),
    ];

    let rejects = vec![
        probe::<GetMerkleProofsRequest>(
            "pubkey-short",
            "pubkey",
            "merkleProofsRequest",
            json!({
                "tree_account": "short",
                "leaves": [hash_str],
            }),
        ),
        probe::<GetEncryptedUtxosByTagsResponse>(
            "signature-short",
            "signature",
            "encryptedUtxosResponse",
            {
                let mut body = valid_encrypted.clone();
                body["matches"][0]["tx_signature"] = json!("not-a-signature");
                body
            },
        ),
        probe::<GetRingsByTagsRequest>(
            "rings-request-bad-cursor",
            "invalidBase64",
            "ringsByTagsRequest",
            json!({
                "tags": [hash_str],
                "cursor": "not-base64",
            }),
        ),
        probe::<GetRingsByTagsRequest>(
            "rings-request-limit-zero",
            "invalidLimit",
            "ringsByTagsRequest",
            json!({
                "tags": [hash_str],
                "limit": 0,
            }),
        ),
        probe::<GetMerkleProofsRequest>(
            "merkle-request-bad-tree",
            "invalidAddress",
            "merkleProofsRequest",
            json!({
                "tree_account": "short",
                "leaves": [hash_str],
            }),
        ),
        probe::<GetMerkleProofsRequest>(
            "merkle-request-leaves-wrong-type",
            "invalidType",
            "merkleProofsRequest",
            json!({
                "tree_account": tree_str,
                "leaves": "bad",
            }),
        ),
        probe::<GetNonInclusionProofsRequest>(
            "non-inclusion-request-leaves-wrong-type",
            "invalidType",
            "nonInclusionProofsRequest",
            json!({
                "tree_account": tree_str,
                "leaves": "bad",
            }),
        ),
        probe::<GetNullifierQueueElementsRequest>(
            "queue-request-limit-above-page",
            "invalidLimit",
            "nullifierQueueRequest",
            json!({
                "tree_account": tree_str,
                "limit": PAGE_LIMIT + 1,
            }),
        ),
        probe::<GetNullifierQueueElementsRequest>(
            "queue-request-unknown-cursor",
            "unknownField",
            "nullifierQueueRequest",
            json!({
                "tree_account": tree_str,
                "limit": 1,
                "cursor": "AA==",
            }),
        ),
        probe::<GetEncryptedUtxosByTagsResponse>(
            "encrypted-bad-signature",
            "invalidSignature",
            "encryptedUtxosResponse",
            {
                let mut body = valid_encrypted.clone();
                body["matches"][0]["tx_signature"] = json!(hash_str);
                body
            },
        ),
        probe::<GetEncryptedUtxosByTagsResponse>(
            "encrypted-unknown-field",
            "unknownField",
            "encryptedUtxosResponse",
            {
                let mut body = valid_encrypted.clone();
                body["extra"] = json!(true);
                body
            },
        ),
        probe::<GetShieldedTransactionsByTagsResponse>(
            "shielded-message-unknown-field",
            "unknownField",
            "shieldedTransactionsResponse",
            json!({
                "context": { "block_time": 0 },
                "transactions": [{
                    "slot": 0,
                    "tx_signature": signature_str,
                    "tx_viewing_pk": null,
                    "salt": null,
                    "output_slots": [],
                    "messages": [{
                        "view_tag": hash_str,
                        "payload": "AA==",
                        "extra": 1,
                    }],
                    "nullifiers": [],
                    "proofless": false,
                }],
                "next_cursor": null,
            }),
        ),
        probe::<GetMerkleProofsResponse>(
            "merkle-path-hash-wrong-size",
            "hashWrongSize",
            "merkleProofsResponse",
            {
                let mut body = valid_merkle_response.clone();
                body["proofs"][0]["path"] = json!([hash_str, "short"]);
                body
            },
        ),
        probe::<GetMerkleProofsResponse>(
            "merkle-leaf-index-negative",
            "invalidInteger",
            "merkleProofsResponse",
            {
                let mut body = valid_merkle_response.clone();
                body["proofs"][0]["leaf_index"] = json!(-1);
                body
            },
        ),
        probe::<GetMerkleProofsResponse>(
            "merkle-root-index-above-u16",
            "invalidInteger",
            "merkleProofsResponse",
            {
                let mut body = valid_merkle_response.clone();
                body["proofs"][0]["root_index"] = json!(65_536);
                body
            },
        ),
        probe::<GetMerkleProofsResponse>(
            "merkle-tree-type-above-u16",
            "invalidInteger",
            "merkleProofsResponse",
            {
                let mut body = valid_merkle_response.clone();
                body["proofs"][0]["merkle_context"]["tree_type"] = json!(65_536);
                body
            },
        ),
        probe::<GetMerkleProofsResponse>(
            "merkle-leaf-index-decimal-string",
            "boundedIntegerString",
            "merkleProofsResponse",
            {
                let mut body = valid_merkle_response.clone();
                body["proofs"][0]["leaf_index"] = json!("7");
                body
            },
        ),
        probe::<GetNonInclusionProofsResponse>(
            "non-inclusion-high-index-negative",
            "invalidInteger",
            "nonInclusionProofsResponse",
            {
                let mut body = valid_non_inclusion.clone();
                body["proofs"][0]["high_element_index"] = json!(-1);
                body
            },
        ),
        probe::<GetNonInclusionProofsResponse>(
            "non-inclusion-inclusion-only-leaf-index",
            "unknownField",
            "nonInclusionProofsResponse",
            {
                let mut body = valid_non_inclusion.clone();
                body["proofs"][0]["leaf_index"] = json!(0);
                body
            },
        ),
        probe::<GetNullifierQueueElementsResponse>(
            "queue-seq-negative",
            "invalidInteger",
            "nullifierQueueResponse",
            json!({
                "context": { "block_time": 0 },
                "elements": [{ "seq": -1, "value": hash_str }],
            }),
        ),
        probe::<GetEncryptedUtxosByTagsResponse>(
            "encrypted-response-unknown-field",
            "unknownField",
            "encryptedUtxosResponse",
            {
                let mut body = valid_encrypted.clone();
                body["unknown"] = json!(true);
                body
            },
        ),
        probe::<GetShieldedTransactionsByTagsResponse>(
            "shielded-response-unknown-field",
            "unknownField",
            "shieldedTransactionsResponse",
            json!({
                "context": { "block_time": 0 },
                "transactions": [],
                "next_cursor": null,
                "unknown": true,
            }),
        ),
        probe::<GetMerkleProofsResponse>(
            "merkle-response-unknown-field",
            "unknownField",
            "merkleProofsResponse",
            {
                let mut body = valid_merkle_response.clone();
                body["unknown"] = json!(true);
                body
            },
        ),
        probe::<GetNonInclusionProofsResponse>(
            "non-inclusion-response-unknown-field",
            "unknownField",
            "nonInclusionProofsResponse",
            {
                let mut body = valid_non_inclusion.clone();
                body["unknown"] = json!(true);
                body
            },
        ),
        probe::<GetNullifierQueueElementsResponse>(
            "queue-response-unknown-field",
            "unknownField",
            "nullifierQueueResponse",
            json!({
                "context": { "block_time": 0 },
                "elements": [],
                "unknown": true,
            }),
        ),
    ];

    // Tamper cases start from a body Rust accepts and flip one field. The suite
    // must refuse the mutated body; a one-sided acceptor would keep passing.
    let tampers = vec![
        probe::<GetMerkleProofsResponse>(
            "tamper-merkle-path-entry",
            "tamper",
            "merkleProofsResponse",
            {
                let mut body = valid_merkle_response.clone();
                body["proofs"][0]["path"] = json!([hash_str, "short"]);
                body
            },
        ),
        probe::<GetEncryptedUtxosByTagsResponse>(
            "tamper-encrypted-add-field",
            "tamper",
            "encryptedUtxosResponse",
            {
                let mut body = valid_encrypted.clone();
                body["matches"][0]["forged"] = json!(true);
                body
            },
        ),
        probe::<GetRingsByTagsRequest>(
            "tamper-rings-limit-past-page",
            "tamper",
            "ringsByTagsRequest",
            {
                let mut body = valid_rings_request.clone();
                body["limit"] = json!(PAGE_LIMIT + 1);
                body
            },
        ),
        probe::<GetNonInclusionProofsResponse>(
            "tamper-non-inclusion-inject-leaf-index",
            "tamper",
            "nonInclusionProofsResponse",
            {
                let mut body = valid_non_inclusion.clone();
                body["proofs"][0]["leaf_index"] = json!(0);
                body
            },
        ),
    ];

    // Acceptance controls pin the seeds the tampers mutate against.
    let accepts = vec![
        accept::<GetMerkleProofsResponse>(
            "control-merkle-response",
            "merkleProofsResponse",
            valid_merkle_response,
        ),
        accept::<GetRingsByTagsRequest>(
            "control-rings-request",
            "ringsByTagsRequest",
            valid_rings_request,
        ),
        accept::<GetEncryptedUtxosByTagsResponse>(
            "control-encrypted-response",
            "encryptedUtxosResponse",
            valid_encrypted,
        ),
        accept::<GetNonInclusionProofsResponse>(
            "control-non-inclusion-response",
            "nonInclusionProofsResponse",
            valid_non_inclusion,
        ),
        accept::<Limit>("control-limit-min", "limit", json!(1)),
        accept::<Limit>("control-limit-page", "limit", json!(PAGE_LIMIT)),
        accept::<GetEncryptedUtxosByTagsResponse>(
            "control-block-time-decimal-string",
            "encryptedUtxosResponse",
            json!({
                "context": { "block_time": "9007199254740993" },
                "matches": [],
                "next_cursor": null,
            }),
        ),
        accept::<GetNullifierQueueElementsResponse>(
            "control-seq-decimal-string",
            "nullifierQueueResponse",
            json!({
                "context": { "block_time": 0 },
                "elements": [{ "seq": "9007199254740993", "value": hash_str }],
            }),
        ),
    ];

    Ok(json!({
        "accepts": accepts,
        "generatorCommand": "cargo run -p xtask --bin indexer-schema-rejects",
        "id": "indexer-schema-rejects-v1",
        "rejects": rejects,
        "responsibility": concat!(
            "Rust oracle for @zolana/indexer-api schema rejection and tamper ",
            "cases: production serde Deserialize of every request/response ",
            "family, scalar bounds, deny_unknown_fields, and mutated success bodies."
        ),
        "rustPath": "sdk-libs/indexer-api/src/lib.rs",
        "rustSymbol": "Deserialize for request/response/scalar wire types",
        "scalars": scalars,
        "schema": "zolana-ts-fixtures-v1",
        "tampers": tampers,
        "version": "1",
    }))
}

fn probe_scalar<T>(id: &str, kind: &str, surface: &str, wire: Value) -> Value
where
    T: serde::de::DeserializeOwned,
{
    match serde_json::from_value::<T>(wire.clone()) {
        Ok(_) => panic!("scalar case {id} was accepted by Rust"),
        Err(error) => json!({
            "accepted": false,
            "id": id,
            "kind": kind,
            "rustError": error.to_string(),
            "surface": surface,
            "wire": wire,
        }),
    }
}

fn probe<T>(id: &str, kind: &str, surface: &str, wire: Value) -> Value
where
    T: serde::de::DeserializeOwned,
{
    match serde_json::from_value::<T>(wire.clone()) {
        Ok(_) => panic!("rejection case {id} was accepted by Rust"),
        Err(error) => json!({
            "accepted": false,
            "id": id,
            "kind": kind,
            "rustError": error.to_string(),
            "surface": surface,
            "wire": wire,
        }),
    }
}

fn accept<T>(id: &str, surface: &str, wire: Value) -> Value
where
    T: serde::de::DeserializeOwned,
{
    match serde_json::from_value::<T>(wire.clone()) {
        Ok(_) => json!({
            "accepted": true,
            "id": id,
            "surface": surface,
            "wire": wire,
        }),
        Err(error) => panic!("acceptance case {id} was refused by Rust: {error}"),
    }
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
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
