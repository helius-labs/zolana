//! End-to-end ring-proof tests: build a witness in Rust, prove it with
//! `squads-prover`, and verify it on the host against the committed on-chain ring
//! verifying key.
//!
//! Run with:
//!   cargo test --manifest-path rings/squads/Cargo.toml -p zolana-squads-sdk \
//!     --features prover -- --nocapture

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::{Groth16Verifier, Groth16Verifyingkey},
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::X25519Keypair;
use zolana_squads_interface::verifying_keys::{ring_1_1, ring_2_2};

use crate::prover::{
    error::SquadsProverError,
    ring::{
        decrypt_sender_change, derive_spend_secrets, right_align_u64, RingProofResult,
        RingRecipient, RingUtxo, RingWitness, UTXO_DOMAIN,
    },
};

/// A random field element below both the BN254 modulus and the X25519 order.
fn random_field() -> [u8; 32] {
    let mut b = *X25519Keypair::new().secret_bytes();
    b[0] = 0;
    b
}

fn verify_on_host(
    proof: &RingProofResult,
    vk: &Groth16Verifyingkey,
    public_input: &[u8; 32],
) -> bool {
    let chunk =
        |start: usize, len: usize| proof.proof.get(start..start + len).expect("proof chunk");
    let proof_a = decompress_g1(chunk(0, 32).try_into().expect("a")).expect("decompress a");
    let proof_b = decompress_g2(chunk(32, 64).try_into().expect("b")).expect("decompress b");
    let proof_c = decompress_g1(chunk(96, 32).try_into().expect("c")).expect("decompress c");
    let commitment =
        decompress_g1(chunk(128, 32).try_into().expect("commitment")).expect("commitment");
    let pok = decompress_g1(chunk(160, 32).try_into().expect("pok")).expect("pok");
    let public_inputs = [*public_input];
    Groth16Verifier::new_with_commitment(
        &proof_a,
        &proof_b,
        &proof_c,
        &commitment,
        &pok,
        &public_inputs,
        vk,
    )
    .expect("verifier construction")
    .verify()
    .is_ok()
}

struct Sender {
    viewing: X25519Keypair,
    nullifier_secret: [u8; 32],
    nullifier_pubkey: [u8; 32],
    owner: [u8; 32],
}

fn sender() -> Sender {
    let nullifier_secret = random_field();
    Sender {
        viewing: X25519Keypair::new(),
        nullifier_pubkey: Poseidon::hashv(&[nullifier_secret.as_slice()]).expect("poseidon"),
        nullifier_secret,
        owner: random_field(),
    }
}

fn utxo(owner: [u8; 32], nullifier_pubkey: [u8; 32], amount: u64, blinding: [u8; 32]) -> RingUtxo {
    RingUtxo {
        domain: UTXO_DOMAIN,
        tree_id: 1,
        owner_key_hash: owner,
        nullifier_pubkey,
        asset: [0u8; 32],
        amount,
        blinding,
        program_data_hash: [0u8; 32],
        ring_data_hash: [0u8; 32],
        ring_program_id: random_field(),
    }
}

/// Inputs plus the change (and recipient) outputs, with the blindings the
/// circuit derives from the first nullifier.
fn spend(
    sender: &Sender,
    inputs: Vec<RingUtxo>,
    change: u64,
    recipient: Option<(&RingRecipient, u64)>,
    public_amount: u64,
) -> RingWitness {
    let first = inputs.first().expect("first input");
    let first_nullifier = Poseidon::hashv(&[
        first.hash().expect("hash").as_slice(),
        first.blinding.as_slice(),
        sender.nullifier_secret.as_slice(),
    ])
    .expect("nullifier");
    let secrets = derive_spend_secrets(&sender.viewing, &first_nullifier).expect("secrets");
    let ring_program_id = first.ring_program_id;
    let mut change = utxo(
        sender.owner,
        sender.nullifier_pubkey,
        change,
        secrets.change_blinding,
    );
    change.ring_program_id = ring_program_id;
    let mut outputs = vec![change];
    if let Some((recipient, amount)) = recipient {
        let mut output = utxo(
            recipient.owner_key_hash,
            recipient.nullifier_pubkey,
            amount,
            secrets.recipient_blinding,
        );
        output.ring_program_id = ring_program_id;
        outputs.push(output);
    }
    RingWitness {
        viewing_secret_key: sender.viewing.clone(),
        nullifier_secret: sender.nullifier_secret,
        inputs,
        outputs,
        external_data_hash: random_field(),
        recipient: recipient.map(|(recipient, _)| recipient.clone()),
        proposal: None,
        public_amount: right_align_u64(public_amount),
    }
}

fn recipient() -> RingRecipient {
    RingRecipient {
        owner_key_hash: random_field(),
        nullifier_pubkey: random_field(),
        viewing_pubkey: X25519Keypair::new().pubkey(),
    }
}

#[test]
fn decrypt_sender_change_recovers_the_change_from_the_first_nullifier() {
    let sender = sender();
    let first_nullifier = random_field();
    let secrets = derive_spend_secrets(&sender.viewing, &first_nullifier).expect("secrets");
    let ciphertext =
        crate::encrypted_utxo::encrypt_sender_ciphertext(&secrets.tx_viewing_sk, 600, &[7u8; 32])
            .expect("encrypt");

    let (amount, asset, blinding) =
        decrypt_sender_change(&sender.viewing, &first_nullifier, &ciphertext).expect("decrypt");

    assert_eq!(
        (amount, asset, blinding),
        (600, [7u8; 32], secrets.change_blinding)
    );
}

#[test]
fn ring_prove_rejects_a_change_blinding_not_derived_from_the_first_nullifier() {
    let sender = sender();
    let inputs = vec![utxo(
        sender.owner,
        sender.nullifier_pubkey,
        10,
        random_field(),
    )];
    let mut witness = spend(&sender, inputs, 3, None, 7);
    if let Some(change) = witness.outputs.first_mut() {
        change.blinding = random_field();
    }
    assert!(matches!(
        witness.private_tx_hash(),
        Err(SquadsProverError::BlindingMismatch)
    ));
}

#[test]
fn ring_prove_rejects_dummy_first_input() {
    let sender = sender();
    let real = utxo(sender.owner, sender.nullifier_pubkey, 10, random_field());
    let mut witness = spend(
        &sender,
        vec![real, RingUtxo::dummy(1, random_field())],
        6,
        Some((&recipient(), 4)),
        0,
    );
    witness.inputs.reverse();
    assert!(matches!(
        witness.private_tx_hash(),
        Err(SquadsProverError::DummyFirstInput)
    ));
}

#[test]
fn ring_transfer_2_2_proof_verifies_end_to_end() {
    let sender = sender();
    let inputs = vec![
        utxo(sender.owner, sender.nullifier_pubkey, 700, random_field()),
        utxo(sender.owner, sender.nullifier_pubkey, 300, random_field()),
    ];
    let recipient = recipient();
    let proof = spend(&sender, inputs, 600, Some((&recipient, 400)), 0)
        .prove()
        .expect("proof generation must succeed");

    assert_eq!(proof.ciphertexts.sender.len(), 40);
    assert_eq!(proof.ciphertexts.recipient.as_ref().map(Vec::len), Some(72));
    assert!(verify_on_host(
        &proof,
        &ring_2_2::VERIFYINGKEY,
        &proof.public_input_hash
    ));
    let mut tampered = proof.public_input_hash;
    tampered[1] ^= 1;
    assert!(!verify_on_host(&proof, &ring_2_2::VERIFYINGKEY, &tampered));
}

#[test]
fn ring_transfer_2_2_with_dummy_input_proof_verifies_end_to_end() {
    let sender = sender();
    let inputs = vec![
        utxo(sender.owner, sender.nullifier_pubkey, 1000, random_field()),
        RingUtxo::dummy(1, random_field()),
    ];
    let proof = spend(&sender, inputs, 600, Some((&recipient(), 400)), 0)
        .prove()
        .expect("proof generation must succeed");
    assert!(verify_on_host(
        &proof,
        &ring_2_2::VERIFYINGKEY,
        &proof.public_input_hash
    ));
}

#[test]
fn ring_withdrawal_1_1_proof_verifies_end_to_end() {
    let sender = sender();
    let inputs = vec![utxo(
        sender.owner,
        sender.nullifier_pubkey,
        1000,
        random_field(),
    )];
    let proof = spend(&sender, inputs, 250, None, 750)
        .prove()
        .expect("proof generation must succeed");
    assert!(proof.ciphertexts.recipient.is_none());
    assert!(verify_on_host(
        &proof,
        &ring_1_1::VERIFYINGKEY,
        &proof.public_input_hash
    ));
}
