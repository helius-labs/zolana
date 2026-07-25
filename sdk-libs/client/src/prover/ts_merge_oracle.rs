//! Rust-side oracle for the TypeScript merge parity tests (rows C09 and C17).
//!
//! The merge request body and the merge public-input chain were the two parts of
//! the prover subtree with no Rust-derived evidence: the key set and field names
//! were pinned by hand-written lists that existed in parallel in both languages,
//! and the values were pinned only by a TypeScript-side fixture. Either could
//! drift into a request that the prover answers with a proof of a different
//! statement.
//!
//! This test builds both merge rails from the seeds in
//! `sdk-libs/ts/fixtures/transaction/merge-v1.json`, the ones the TypeScript
//! merge tests already use, and writes what the production `MergeProver`,
//! `MergeZoneProver`, `to_json_merge`, and `to_json_merge_zone` returned to
//! `sdk-libs/ts/client/test/oracles/merge-v1.json`.
//! `sdk-libs/ts/client/test/vectors/merge-oracle.test.ts` rebuilds the same two
//! merges and compares.
//!
//! The serializers are `pub(crate)`, so this generator has to live inside the
//! crate rather than under `tests/`.
//!
//! Regenerate with
//! `ZOLANA_UPDATE_TS_ORACLES=1 cargo test -p zolana-client --lib ts_merge_oracle`.

use std::{path::PathBuf, str::FromStr};

use p256::SecretKey;
use serde_json::{json, Value};
use solana_address::Address;
use zolana_keypair::{NullifierKey, PublicKey, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    derive_blinding,
    instructions::{
        merge::PreparedMerge,
        merge_zone::PreparedMergeZone,
        transact::SppProofOutputUtxo,
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    Data, Utxo, SOL_MINT,
};

use crate::{
    prover::{
        json::{to_json_merge, to_json_merge_zone},
        merge::{MergeProofResult, MergeProver, MergeWitness},
        merge_zone::{MergeZoneProver, MergeZoneWitness},
    },
    MerkleContext, MerkleProof, NonInclusionProof, SpendProof,
};

/// Shared with `sdk-libs/ts/fixtures/transaction/merge-v1.json` and the
/// TypeScript merge tests; the two languages must derive identical key material,
/// blindings, and Merkle context from them.
const SIGNING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const VIEWING_SEED: [u8; 32] = [8; 32];
const BLINDING_SEED: [u8; 31] = [11; 31];
const TX_VIEWING_SECRET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15,
];
const REAL_INPUT_AMOUNTS: [u64; 2] = [10, 20];
const OUTPUT_AMOUNT: u64 = 30;
const MERGE_INPUTS: usize = 8;
const TREE: &str = "4WnNSfDXkWSnFi1PgXxn8X8fhFwU2Jhe4Df82mL9rKmm";
const ZONE_PROGRAM_BYTES: [u8; 32] = [3; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn field_byte(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

fn keypair() -> ShieldedKeypair {
    ShieldedKeypair::from_keys(
        SigningKey::from_bytes(&SIGNING_SECRET).expect("p256 signing key"),
        ViewingKey::from_seed(&VIEWING_SEED, 0).expect("viewing key"),
    )
    .expect("shielded keypair")
}

fn tree() -> Address {
    Address::from_str(TREE).expect("tree address")
}

fn real_input(
    keypair: &ShieldedKeypair,
    position: u8,
    zone_program_id: Option<Address>,
) -> SppProofInputUtxo {
    SppProofInputUtxo::new(
        Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount: REAL_INPUT_AMOUNTS[position as usize],
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id,
            data: Data::default(),
        },
        keypair,
    )
}

/// The dummy slot the TypeScript `ProofInputUtxo.dummy` produces: a zeroed owner,
/// the system asset, zero amount, and the zero nullifier secret. Only the
/// blinding varies per slot.
fn dummy_input(position: u8) -> SppProofInputUtxo {
    SppProofInputUtxo {
        utxo: Utxo {
            owner: PublicKey::zeroed(),
            asset: SOL_MINT,
            amount: 0,
            blinding: derive_blinding(&BLINDING_SEED, position),
            zone_program_id: None,
            data: Data::default(),
        },
        nullifier_key: NullifierKey::from_secret([0; 31]),
        data_hash: None,
        zone_data_hash: None,
    }
}

fn output(keypair: &ShieldedKeypair, zone_program_id: Option<Address>) -> SppProofOutputUtxo {
    SppProofOutputUtxo {
        asset: SOL_MINT,
        amount: OUTPUT_AMOUNT,
        blinding: derive_blinding(&BLINDING_SEED, 2),
        owner_address: Some(keypair.shielded_address().expect("shielded address")),
        zone_program_id,
        ..Default::default()
    }
}

fn inputs(keypair: &ShieldedKeypair, zone_program_id: Option<Address>) -> Vec<SppProofInputUtxo> {
    let mut slots: Vec<SppProofInputUtxo> = (0..REAL_INPUT_AMOUNTS.len() as u8)
        .map(|position| real_input(keypair, position, zone_program_id))
        .collect();
    slots.extend((REAL_INPUT_AMOUNTS.len() as u8..MERGE_INPUTS as u8).map(dummy_input));
    slots
}

/// Mirrors `spendProof` in `sdk-libs/ts/client/test/merge.test.ts`: both proofs
/// name the same tree, the roots and root indexes are per-slot constants, and
/// every path element is zero.
fn spend_proofs(contexts: &[InputUtxoContext]) -> Vec<SpendProof> {
    let tree = tree();
    contexts
        .iter()
        .enumerate()
        .map(|(index, context)| SpendProof {
            state: MerkleProof {
                leaf: context.utxo_hash,
                merkle_context: MerkleContext { tree_type: 1, tree },
                path: vec![[0u8; 32]; 32],
                leaf_index: index as u64,
                root: field_byte(20 + index as u8),
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
                high_element_index: index as u64 + 1,
                root: field_byte(30 + index as u8),
                root_seq: 1,
                root_index: 50 + index as u16,
            },
        })
        .collect()
}

fn build_merge() -> (MergeProofResult, String) {
    let keypair = keypair();
    let prepared = PreparedMerge {
        inputs: inputs(&keypair, None),
        output: output(&keypair, None),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: SecretKey::from_slice(&TX_VIEWING_SECRET).expect("tx viewing scalar"),
    };
    let proofs = spend_proofs(&prepared.input_utxo_hashes().expect("input contexts"));
    let result = MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key: keypair.nullifier_key.clone(),
        proofs,
    })
    .expect("merge prover")
    .build()
    .expect("merge proof result");
    let body = to_json_merge(&result.inputs);
    (result, body)
}

fn build_merge_zone() -> (MergeProofResult, String) {
    let keypair = keypair();
    let zone = Address::new_from_array(ZONE_PROGRAM_BYTES);
    let prepared = PreparedMergeZone {
        inputs: inputs(&keypair, Some(zone)),
        output: output(&keypair, Some(zone)),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: keypair.signing_pubkey(),
        user_viewing_pk: keypair.viewing_pubkey(),
        tx_viewing_sk: SecretKey::from_slice(&TX_VIEWING_SECRET).expect("tx viewing scalar"),
        zone_program_id: zone,
    };
    let proofs = spend_proofs(&prepared.input_utxo_hashes().expect("input contexts"));
    let result = MergeZoneProver::try_from(MergeZoneWitness {
        prepared,
        nullifier_key: keypair.nullifier_key.clone(),
        proofs,
    })
    .expect("merge zone prover")
    .build()
    .expect("merge zone proof result");
    let body = to_json_merge_zone(&result.inputs);
    (result, body)
}

/// The request body is emitted as the raw serialized string so the TypeScript
/// side can compare both the decoded values and the field order serde produced,
/// neither of which survives a round trip through `serde_json::Value`.
fn rail_json(result: &MergeProofResult, body: &str) -> Value {
    json!({
        "requestBodyJson": body,
        "publicInputHashBytes": hex(&result.public_input_hash),
        "outputHashBytes": hex(&result.output_hash),
        "privateTxHashBytes": hex(&result.private_tx_hash),
        "externalDataHashBytes": hex(&result.external_data_hash),
        "nullifierBytes": result.nullifiers.iter().map(|n| hex(n)).collect::<Vec<_>>(),
        "utxoTreeRootIndices": result.utxo_tree_root_indices,
        "nullifierTreeRootIndices": result.nullifier_tree_root_indices,
        "ciphertextBytes": hex(&result.ciphertext),
        "txViewingPkBytes": hex(result.tx_viewing_pk.as_bytes()),
        "eddsaOwner": result.eddsa_owner,
        "expiryUnixTs": result.expiry_unix_ts.to_string(),
    })
}

fn oracle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ts/client/test/oracles/merge-v1.json")
}

#[test]
fn ts_merge_oracle_is_current() {
    let (merge, merge_body) = build_merge();
    let (zone, zone_body) = build_merge_zone();
    let oracle = json!({
        "inputs": {
            "blindingSeedBytes": hex(&BLINDING_SEED),
            "outputAmount": OUTPUT_AMOUNT.to_string(),
            "realInputAmounts": REAL_INPUT_AMOUNTS.iter().map(u64::to_string).collect::<Vec<_>>(),
            "signingSecretBytes": hex(&SIGNING_SECRET),
            "testOnlySecret": true,
            "tree": TREE,
            "txViewingSecretBytes": hex(&TX_VIEWING_SECRET),
            "viewingSeedBytes": hex(&VIEWING_SEED),
            "zoneProgramIdBytes": hex(&ZONE_PROGRAM_BYTES)
        },
        "expected": {
            "merge": rail_json(&merge, &merge_body),
            "mergeZone": rail_json(&zone, &zone_body)
        }
    });
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&oracle).expect("render")
    );

    let path = oracle_path();
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    if current == rendered {
        return;
    }
    std::fs::create_dir_all(path.parent().expect("oracle directory")).expect("create oracle dir");
    std::fs::write(&path, &rendered).expect("write oracle");
    assert!(
        std::env::var_os("ZOLANA_UPDATE_TS_ORACLES").is_some(),
        "{} was stale and has been rewritten; commit it",
        path.display()
    );
}
