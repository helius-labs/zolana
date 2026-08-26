//! Generate and verify a (2,3) transfer proof built from one real input plus
//! dummy padding.
//!
//! Unlike `transaction_proving`, this does not go through the `Transaction`
//! builder. It constructs a `TransferProver` directly with the slots already padded
//! to the (2,3) shape: one zero-value Solana-owned input (the prover requires at
//! least one real input to supply the public tree roots) plus one dummy input, and
//! three dummy outputs. The mechanical prover only converts these slots. The real
//! input carries zero value, so the witness balances at zero and selects the vanilla
//! Solana-only eddsa rail (`transfer_confidential`). The proof is produced on the
//! prover server and verified against the committed verifying key.
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_confidential_2_3.key` proving key available.
//!
//! Run with: `cargo test -p zolana-client --test transfer_dummy`

mod test_indexer;

use rand::RngCore;
use zolana_client::prover::SERVER_ADDRESS;
use zolana_client::{
    spawn_prover, verify_confidential_transfer_proof, InputUtxoContext, ProverClient,
    PublicTransfers, Rpc, Shape, TransferProver, TransferSpendInput,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_transaction::{
    instructions::types::SppProofInputUtxo, Data, ExternalData, SppProofOutputUtxo, Utxo, SOL_MINT,
};

use crate::test_indexer::TestIndexer;

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        if std::env::var_os("ZOLANA_PROVER_KEYS_DIR").is_none() {
            std::env::set_var(
                "ZOLANA_PROVER_KEYS_DIR",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../prover/server/proving-keys"
                ),
            );
        }
    });
    spawn_prover().expect("start prover");
}

fn async_queue_result_count() -> Option<u64> {
    if std::env::var("ZOLANA_EXPECT_ASYNC_PROVER").as_deref() != Ok("true") {
        return None;
    }

    let server = std::env::var("ZOLANA_PROVER_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| SERVER_ADDRESS.to_string());
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .expect("build queue stats client")
        .get(format!("{server}/queue/stats"))
        .send()
        .expect("request Redis queue stats")
        .error_for_status()
        .expect("Redis queue stats endpoint is available")
        .json::<serde_json::Value>()
        .expect("parse Redis queue stats");
    let queues = response
        .get("queues")
        .and_then(serde_json::Value::as_object)
        .expect("queue stats contain queues");
    assert!(
        queues.contains_key("zk_transfer_queue"),
        "transfer queue is registered"
    );
    assert!(
        queues.contains_key("zk_transfer_processing_queue"),
        "transfer processing queue is registered"
    );
    Some(
        queues
            .get("zk_results_queue")
            .and_then(serde_json::Value::as_u64)
            .expect("queue stats contain the results queue"),
    )
}

fn dummy_external_data(owner_tag: [u8; 32], n_outputs: usize) -> ExternalData {
    ExternalData {
        instruction_discriminator: zolana_interface::instruction::tag::TRANSACT,
        expiry_unix_ts: 0,
        interface_transfers: Vec::new(),
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        outputs: (0..n_outputs)
            .map(|_| TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: OwnerTag::Inline(owner_tag),
                data: None,
            })
            .collect(),
        resolved_owner_tags: vec![owner_tag; n_outputs],
        messages: Vec::new(),
    }
}

/// A single zero-value Solana-owned input with its inclusion / non-inclusion
/// proofs served by a fresh `TestIndexer`.
fn real_input() -> TransferSpendInput {
    let mut rng = rand::thread_rng();
    let mut owner_bytes = [0u8; 32];
    rng.fill_bytes(&mut owner_bytes);
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding[1..]);
    let mut secret = [0u8; 31];
    rng.fill_bytes(&mut secret);
    let nullifier_key = NullifierKey::from_secret(secret);

    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&owner_bytes),
        asset: SOL_MINT,
        amount: 0,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };

    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo_hash = utxo
        .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
        .expect("utxo hash");
    let nullifier = utxo
        .nullifier(&utxo_hash, &nullifier_key)
        .expect("nullifier");

    let mut indexer = TestIndexer::new();
    indexer.add_utxo(utxo_hash);
    let proof = indexer
        .get_input_merkle_proofs(
            &[InputUtxoContext {
                index: 0,
                utxo_hash,
                nullifier,
            }],
            None,
        )
        .expect("input merkle proofs")
        .pop()
        .expect("one proof");

    TransferSpendInput {
        utxo,
        nullifier_key,
        data_hash: None,
        ring_data_hash: None,
        proof: Some(proof),
        nullifier_proof: None,
    }
}

/// A padding input: zero owner, random blinding, no state proof. The prover
/// mirrors the first real input's state root onto it; the non-inclusion witness
/// for its own nullifier comes from a fresh tree (the circuit checks
/// non-inclusion per slot against the slot's own root).
fn dummy_input() -> TransferSpendInput {
    let mut blinding = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut blinding[1..]);
    let utxo = Utxo {
        owner: PublicKey::zeroed(),
        asset: SOL_MINT,
        amount: 0,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    let mut spend = SppProofInputUtxo::new_dummy();
    spend.utxo.blinding = blinding;
    let nullifier = spend.nullifier().expect("dummy nullifier");
    let nullifier_proof = TestIndexer::new().dummy_nullifier_proof(nullifier);
    TransferSpendInput {
        utxo,
        nullifier_key: NullifierKey::from_secret([0u8; 31]),
        data_hash: None,
        ring_data_hash: None,
        proof: None,
        nullifier_proof: Some(nullifier_proof),
    }
}

/// A padding output tagged to a real input owner, with random blinding.
fn dummy_output(owner_tag: [u8; 32]) -> SppProofOutputUtxo {
    let mut blinding = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut blinding[1..]);
    SppProofOutputUtxo {
        blinding,
        owner_tag: Some(owner_tag),
        ..Default::default()
    }
}

/// Generate a dummy eddsa transfer proof for `shape` (one real input padded with
/// dummies) on the prover server and verify it through the shipped verifier,
/// which resolves the committed `transfer_confidential_{shape}` key itself.
/// Exercises proof generation + on-chain-style Groth16 verification for every
/// supported shape, not just (2,3) -- and, because it is the shipped path, the
/// shape-to-key mapping the SDK will use in production rather than a copy.
fn prove_and_verify_eddsa_shape(n_in: usize, n_out: usize) {
    let real_input = real_input();
    let owner_tag = real_input
        .utxo
        .owner
        .confidential_view_tag()
        .expect("real input owner tag");
    let mut inputs = vec![real_input];
    for _ in 1..n_in {
        inputs.push(dummy_input());
    }
    let outputs = (0..n_out).map(|_| dummy_output(owner_tag)).collect();
    let mut signer_pk_hashes = vec![[0u8; 32]; n_in + 1];
    signer_pk_hashes[1] = hash_bytes(&owner_tag).expect("owner signer hash");

    let prover = TransferProver {
        private_tx_blinding: zolana_transaction::instructions::transact::new_private_tx_blinding(),
        inputs,
        outputs,
        external_data: dummy_external_data(owner_tag, n_out),
        public_transfers: PublicTransfers::default(),
        signer_pk_hashes,
        allow_dummy_inputs: true,
        shape: Some(Shape::new(n_in, n_out)),
    };
    let result = prover
        .build()
        .unwrap_or_else(|e| panic!("build {n_in}x{n_out} witness: {e:?}"));

    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
        .unwrap_or_else(|e| panic!("prove {n_in}x{n_out}: {e:?}"));

    verify_confidential_transfer_proof(&result, &proof)
        .unwrap_or_else(|e| panic!("verify {n_in}x{n_out}: {e:?}"));
}

/// Sweep: prove + verify an eddsa transfer for every supported shape against its
/// committed verifying key, so each shape's confidential vk has client-side
/// proof-generation coverage (previously only (2,3) was exercised).
#[test]
fn eddsa_transfer_all_shapes_proofs_verify() {
    start_prover();
    for (n_in, n_out) in [
        (1, 1),
        (1, 2),
        (2, 2),
        (2, 3),
        (3, 3),
        (4, 3),
        (4, 4),
        (5, 3),
        (5, 4),
        (1, 8),
    ] {
        prove_and_verify_eddsa_shape(n_in, n_out);
    }
}

#[test]
fn dummy_transfer_2_3_proof_verifies() {
    start_prover();
    let queued_results_before = async_queue_result_count();

    let real_input = real_input();
    let owner_tag = real_input
        .utxo
        .owner
        .confidential_view_tag()
        .expect("real input owner tag");
    let prover = TransferProver {
        private_tx_blinding: zolana_transaction::instructions::transact::new_private_tx_blinding(),
        inputs: vec![real_input, dummy_input()],
        outputs: vec![
            dummy_output(owner_tag),
            dummy_output(owner_tag),
            dummy_output(owner_tag),
        ],
        external_data: dummy_external_data(owner_tag, 3),
        public_transfers: PublicTransfers::default(),
        signer_pk_hashes: vec![
            [0u8; 32],
            hash_bytes(&owner_tag).expect("owner signer hash"),
            [0u8; 32],
        ],
        allow_dummy_inputs: true,
        shape: Some(Shape::new(2, 3)),
    };

    let result = prover.build().expect("build witness with one real input");

    // The queue is what this test covers, and transfers otherwise take the
    // faster in-response rail, so ask for the queued one where it is being
    // asserted on.
    let client = ProverClient::local();
    let client = if queued_results_before.is_some() {
        client.with_queued_proofs()
    } else {
        client
    };
    let proof = client
        .prove_transfer(&result.inputs)
        .expect("prove transfer-eddsa");

    verify_confidential_transfer_proof(&result, &proof).expect("groth16 proof verifies");

    if let Some(before) = queued_results_before {
        let after = async_queue_result_count().expect("async queue stats remain available");
        assert_eq!(
            after,
            before + 1,
            "the transfer proof must complete through TransferQueueWorker"
        );
    }
}
