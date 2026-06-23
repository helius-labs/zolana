//! Generate and verify a (2,3) transfer proof built from one real input plus
//! dummy padding.
//!
//! Unlike `transaction_proving`, this does not go through the `Transaction`
//! builder. It constructs a `TransferProver` directly with the slots already padded
//! to the (2,3) shape: one zero-value Solana-owned input (the prover requires at
//! least one real input to supply the public tree roots) plus one dummy input, and
//! three dummy outputs. The mechanical prover only converts these slots. The real
//! input carries zero value, so the witness balances at zero and selects the vanilla
//! Solana-only eddsa rail (`transfer_2_3`). The proof is produced on the prover
//! server and verified against the committed verifying key.
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_2_3.key` proving key available.
//!
//! Run with: `cargo test -p zolana-client --test transfer_dummy`

mod test_indexer;

use groth16_solana::groth16::Groth16Verifier;
use rand::RngCore;
use solana_address::Address;
use zolana_client::{
    spawn_prover, InputCommitment, ProverClient, PublicAmounts, Rpc, ScopedSpendWitness, Shape,
    SpendWitnessRequest, TransferProver, TransferSpendInput,
};
use zolana_interface::instruction::instruction_data::transact::OutputCiphertext;
use zolana_interface::verifying_keys::transfer_2_3;
use zolana_keypair::{NullifierKey, PublicKey};
use zolana_transaction::{Data, ExternalData, OutputUtxo, Utxo, SOL_MINT};

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
        cpi_signer: None,
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

    let witness = ScopedSpendWitness::from_nullifier_key(
        &SpendWitnessRequest::new(utxo.clone()),
        &nullifier_key,
    )
    .expect("spend witness");

    TransferSpendInput {
        utxo,
        witness,
        proof: Some(proof),
    }
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
        witness: ScopedSpendWitness {
            nullifier_pubkey: [0u8; 32],
            nullifier: [0u8; 32],
            nullifier_secret: [0u8; 31],
        },
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
        &transfer_2_3::VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}
