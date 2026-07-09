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

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use rand::RngCore;
use solana_address::Address;
use zolana_client::{
    assemble, spawn_prover, InputCommitment, ProverClient, ProverInputs, PublicAmounts, Rpc, Shape,
    SpendUtxo, Transaction, TransferProver, TransferSpendInput,
};
use zolana_interface::{
    instruction::instruction_data::transact::OutputCiphertext,
    verifying_keys::{
        transfer_confidential_1_1, transfer_confidential_1_2, transfer_confidential_1_8,
        transfer_confidential_2_2, transfer_confidential_2_3, transfer_confidential_3_3,
        transfer_confidential_4_3, transfer_confidential_4_4, transfer_confidential_5_3,
        transfer_confidential_5_4,
    },
};
use zolana_keypair::{NullifierKey, PublicKey, ShieldedKeypair};
use zolana_transaction::{
    serialization::{
        split::{Split, SplitEncode},
        UtxoSerialization,
    },
    AssetRegistry, Data, ExternalData, OutputUtxo, Utxo, SOL_MINT,
};

use crate::test_indexer::TestIndexer;

fn start_prover() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::env::set_var(
            "ZOLANA_PROVER_KEYS_DIR",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../prover/server/proving-keys"
            ),
        );
    });
    spawn_prover().expect("start prover");
}

fn dummy_external_data() -> ExternalData {
    ExternalData {
        instruction_discriminator: 0,
        expiry_unix_ts: 0,
        relayer_fee: 0,
        public_sol_amount: None,
        public_spl_amount: None,
        user_sol_account: Address::default(),
        user_spl_token: Address::default(),
        spl_token_interface: Address::default(),
        data_hash: None,
        zone_data_hash: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        output_utxo_hashes: vec![[0u8; 32]; 3],
        output_ciphertexts: (0..2)
            .map(|_| OutputCiphertext {
                view_tag: [0u8; 32],
                data: Vec::new(),
            })
            .collect(),
    }
}

/// A single zero-value Solana-owned input with its inclusion / non-inclusion
/// proofs served by a fresh `TestIndexer`.
fn real_input() -> TransferSpendInput {
    let mut rng = rand::thread_rng();
    let mut owner_bytes = [0u8; 32];
    rng.fill_bytes(&mut owner_bytes);
    let mut blinding = [0u8; 31];
    rng.fill_bytes(&mut blinding);
    let mut secret = [0u8; 31];
    rng.fill_bytes(&mut secret);
    let nullifier_key = NullifierKey::from_secret(secret);

    let utxo = Utxo {
        owner: PublicKey::from_ed25519(&owner_bytes),
        asset: SOL_MINT,
        amount: 0,
        blinding,
        zone_program_id: None,
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
        .get_input_merkle_proofs(&[InputCommitment {
            index: 0,
            utxo_hash,
            nullifier,
        }])
        .expect("input merkle proofs")
        .pop()
        .expect("one proof");

    TransferSpendInput {
        utxo,
        nullifier_key,
        data_hash: None,
        zone_data_hash: None,
        proof: Some(proof),
    }
}

fn real_inputs(count: usize) -> (Vec<TransferSpendInput>, u64) {
    let mut rng = rand::thread_rng();
    let mut indexer = TestIndexer::new();
    let mut raw = Vec::with_capacity(count);
    let mut commitments = Vec::with_capacity(count);
    let mut total = 0u64;

    for index in 0..count {
        let mut owner_bytes = [0u8; 32];
        rng.fill_bytes(&mut owner_bytes);
        let mut blinding = [0u8; 31];
        rng.fill_bytes(&mut blinding);
        let mut secret = [0u8; 31];
        rng.fill_bytes(&mut secret);
        let nullifier_key = NullifierKey::from_secret(secret);
        let amount = 10 + u64::try_from(index).expect("test index fits in u64");
        total = total.checked_add(amount).expect("test amounts fit");

        let utxo = Utxo {
            owner: PublicKey::from_ed25519(&owner_bytes),
            asset: SOL_MINT,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
        let utxo_hash = utxo
            .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        let nullifier = utxo
            .nullifier(&utxo_hash, &nullifier_key)
            .expect("nullifier");
        indexer.add_utxo(utxo_hash);
        commitments.push(InputCommitment {
            index,
            utxo_hash,
            nullifier,
        });
        raw.push((utxo, nullifier_key));
    }

    let proofs = indexer
        .get_input_merkle_proofs(&commitments)
        .expect("input merkle proofs");
    let inputs = raw
        .into_iter()
        .zip(proofs)
        .map(|((utxo, nullifier_key), proof)| TransferSpendInput {
            utxo,
            nullifier_key,
            data_hash: None,
            zone_data_hash: None,
            proof: Some(proof),
        })
        .collect();
    (inputs, total)
}

/// A padding input: zero owner, random blinding, no proof. The prover mirrors the
/// first real input's roots onto it.
fn dummy_input() -> TransferSpendInput {
    let mut blinding = [0u8; 31];
    rand::thread_rng().fill_bytes(&mut blinding);
    let utxo = Utxo {
        owner: PublicKey::zeroed(),
        asset: SOL_MINT,
        amount: 0,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    TransferSpendInput {
        utxo,
        nullifier_key: NullifierKey::from_secret([0u8; 31]),
        data_hash: None,
        zone_data_hash: None,
        proof: None,
    }
}

/// A padding output: zero owner hash, random blinding.
fn dummy_output() -> OutputUtxo {
    let mut blinding = [0u8; 31];
    rand::thread_rng().fill_bytes(&mut blinding);
    OutputUtxo {
        blinding,
        ..Default::default()
    }
}

fn real_output(amount: u64) -> OutputUtxo {
    let recipient = ShieldedKeypair::new().expect("recipient");
    let mut blinding = [0u8; 31];
    rand::thread_rng().fill_bytes(&mut blinding);
    OutputUtxo {
        owner_address: Some(recipient.shielded_address().expect("recipient address")),
        asset: SOL_MINT,
        amount,
        blinding,
        ..Default::default()
    }
}

/// The committed eddsa-rail (confidential) verifying key for a shape.
fn eddsa_confidential_vk(n_in: usize, n_out: usize) -> &'static Groth16Verifyingkey<'static> {
    match (n_in, n_out) {
        (1, 1) => &transfer_confidential_1_1::VERIFYINGKEY,
        (1, 2) => &transfer_confidential_1_2::VERIFYINGKEY,
        (2, 2) => &transfer_confidential_2_2::VERIFYINGKEY,
        (2, 3) => &transfer_confidential_2_3::VERIFYINGKEY,
        (3, 3) => &transfer_confidential_3_3::VERIFYINGKEY,
        (4, 3) => &transfer_confidential_4_3::VERIFYINGKEY,
        (4, 4) => &transfer_confidential_4_4::VERIFYINGKEY,
        (5, 3) => &transfer_confidential_5_3::VERIFYINGKEY,
        (5, 4) => &transfer_confidential_5_4::VERIFYINGKEY,
        (1, 8) => &transfer_confidential_1_8::VERIFYINGKEY,
        _ => panic!("unsupported shape {n_in}x{n_out}"),
    }
}

/// Generate a dummy eddsa transfer proof for `shape` (one real input padded with
/// dummies) on the prover server and verify it against the committed
/// `transfer_confidential_{shape}` verifying key. Exercises proof generation +
/// on-chain-style Groth16 verification for every supported shape, not just (2,3).
fn prove_and_verify_eddsa_shape(n_in: usize, n_out: usize) {
    let mut inputs = vec![real_input()];
    for _ in 1..n_in {
        inputs.push(dummy_input());
    }
    let outputs = (0..n_out).map(|_| dummy_output()).collect();

    let prover = TransferProver {
        inputs,
        outputs,
        external_data: dummy_external_data(),
        public_amounts: PublicAmounts {
            sol: [0u8; 32],
            spl: [0u8; 32],
            asset: [0u8; 32],
        },
        payer_pubkey_hash: [0u8; 32],
        shape: Some(Shape::new(n_in, n_out)),
    };
    prove_and_verify_eddsa_prover(prover, n_in, n_out);
}

fn prove_and_verify_eddsa_prover(prover: TransferProver, n_in: usize, n_out: usize) {
    let result = prover
        .build()
        .unwrap_or_else(|e| panic!("build {n_in}x{n_out} witness: {e:?}"));

    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
        .unwrap_or_else(|e| panic!("prove {n_in}x{n_out}: {e:?}"));

    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        eddsa_confidential_vk(n_in, n_out),
    )
    .unwrap_or_else(|e| panic!("construct {n_in}x{n_out} verifier: {e:?}"));
    verifier
        .verify()
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
fn eddsa_transfer_multi_real_inputs_proofs_verify() {
    start_prover();
    for (shape_inputs, real_count) in [(3usize, 2usize), (3, 3), (4, 4), (5, 5)] {
        let (mut inputs, total) = real_inputs(real_count);
        while inputs.len() < shape_inputs {
            inputs.push(dummy_input());
        }
        let mut outputs = vec![real_output(total)];
        while outputs.len() < 3 {
            outputs.push(dummy_output());
        }
        let prover = TransferProver {
            inputs,
            outputs,
            external_data: dummy_external_data(),
            public_amounts: PublicAmounts {
                sol: [0u8; 32],
                spl: [0u8; 32],
                asset: [0u8; 32],
            },
            payer_pubkey_hash: [0u8; 32],
            shape: Some(Shape::new(shape_inputs, 3)),
        };
        prove_and_verify_eddsa_prover(prover, shape_inputs, 3);
    }
}

#[test]
fn eddsa_split_1x8_proof_verifies() {
    start_prover();
    let owner = ShieldedKeypair::new().expect("owner");
    let mut rng = rand::thread_rng();
    let mut owner_bytes = [0u8; 32];
    rng.fill_bytes(&mut owner_bytes);
    let mut blinding = [0u8; 31];
    rng.fill_bytes(&mut blinding);
    let mut secret = [0u8; 31];
    rng.fill_bytes(&mut secret);
    let nullifier_key = NullifierKey::from_secret(secret);
    let input = Utxo {
        owner: PublicKey::from_ed25519(&owner_bytes),
        asset: SOL_MINT,
        amount: 80,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let mut tx = Transaction::new(
        owner.shielded_address().expect("owner address"),
        vec![SpendUtxo::from_nullifier_key(input, &nullifier_key)],
        Address::default(),
    );
    tx.split(SOL_MINT, 8, 10).expect("split");
    let assets = AssetRegistry::default();
    let prepared = tx.prepare_split(&assets).expect("prepare split");
    let tx_viewing_key = owner
        .get_transaction_viewing_key(&prepared.first_nullifier)
        .expect("tx viewing key");
    let salt = zolana_keypair::random_salt();
    let bundle_plaintext = prepared.bundle_plaintext().expect("bundle plaintext");
    let bundle = Split::encode_plaintext(
        &bundle_plaintext,
        prepared.view_tag().expect("split view tag"),
        &SplitEncode {
            tx: tx_viewing_key.clone(),
            recipient_pubkey: owner.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: prepared.blinding_seed,
        },
    )
    .expect("encode split bundle");
    let signed = prepared
        .finalize(tx_viewing_key.pubkey(), salt, bundle, &assets)
        .expect("finalize split");
    assert_eq!(signed.shape.n_inputs, 1);
    assert_eq!(signed.shape.n_outputs, 8);

    let mut indexer = TestIndexer::new();
    let commitments = signed.input_commitments().expect("commitments");
    for commitment in &commitments {
        indexer.add_utxo(commitment.utxo_hash);
    }
    let proofs = indexer
        .get_input_merkle_proofs(&commitments)
        .expect("input merkle proofs");
    let assembled = assemble(signed, &proofs).expect("assemble split");
    let ProverInputs::Eddsa(inputs) = assembled.prover_inputs else {
        panic!("split over eddsa-owned input should use eddsa rail");
    };
    let proof = ProverClient::local()
        .prove_transfer(&inputs)
        .expect("prove split 1x8");
    let public_inputs: [[u8; 32]; 1] = [assembled.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        eddsa_confidential_vk(1, 8),
    )
    .expect("construct split verifier");
    verifier.verify().expect("split proof verifies");
}

#[test]
fn dummy_transfer_2_3_proof_verifies() {
    start_prover();

    let prover = TransferProver {
        inputs: vec![real_input(), dummy_input()],
        outputs: vec![dummy_output(), dummy_output(), dummy_output()],
        external_data: dummy_external_data(),
        public_amounts: PublicAmounts {
            sol: [0u8; 32],
            spl: [0u8; 32],
            asset: [0u8; 32],
        },
        payer_pubkey_hash: [0u8; 32],
        shape: Some(Shape::new(2, 3)),
    };

    let result = prover.build().expect("build witness with one real input");

    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
        .expect("prove transfer-eddsa");

    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &transfer_confidential_2_3::VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}
