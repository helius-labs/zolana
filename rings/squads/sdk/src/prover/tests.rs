//! End-to-end key-encryption proof test: build a witness in Rust, prove it with
//! `squads-prover`, and verify it on the host against the
//! committed on-chain verifying key using the same public-input hash the on-chain
//! program computes.
//!
//! Run with: `cargo test -p zolana-squads-sdk --features prover -- --nocapture`
//! (the first request lazy-loads a large proving key and takes minutes).

use groth16_solana::{
    decompression::{decompress_g1, decompress_g2},
    groth16::Groth16Verifier,
};
use zolana_keypair::X25519Keypair;
use zolana_squads_interface::verifying_keys::key_encryption_2;

use crate::prover::key_encryption::{KeyEncryptionProofResult, KeyEncryptionWitness};

/// A random BN254-range scalar (top byte cleared so it is < the field modulus).
/// Used for the nullifier secret, which is a BN254 field element by design; the
/// viewing and ephemeral secrets are raw RFC 7748 secret bytes.
fn random_bn254_scalar() -> [u8; 32] {
    let mut b = *X25519Keypair::new().secret_bytes();
    b[0] = 0; // < 2^248 < BN254 modulus.
    b
}

/// Host verification of the 192-byte BSB22 proof, mirroring the program's
/// `verify_groth16` (program/src/shared/proof.rs): decompress the six points and
/// run `Groth16Verifier::new_with_commitment` against `key_encryption_2`.
fn verify_on_host(proof_result: &KeyEncryptionProofResult) -> bool {
    let proof = &proof_result.proof;
    let vk = &key_encryption_2::VERIFYINGKEY;
    assert!(
        vk.vk_commitment.is_some(),
        "key_encryption_2 must be the BSB22 rail",
    );

    let proof_a = decompress_g1(&to32(&proof[0..32])).expect("decompress a");
    let proof_b = decompress_g2(&to64(&proof[32..96])).expect("decompress b");
    let proof_c = decompress_g1(&to32(&proof[96..128])).expect("decompress c");
    let commitment = decompress_g1(&to32(&proof[128..160])).expect("decompress commitment");
    let commitment_pok = decompress_g1(&to32(&proof[160..192])).expect("decompress pok");

    let public_inputs = [proof_result.public_input_hash];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof_a,
        &proof_b,
        &proof_c,
        &commitment,
        &commitment_pok,
        &public_inputs,
        vk,
    )
    .expect("verifier construction");
    verifier.verify().is_ok()
}

fn to32(s: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(s);
    o
}

fn to64(s: &[u8]) -> [u8; 64] {
    let mut o = [0u8; 64];
    o.copy_from_slice(s);
    o
}

#[test]
fn key_encryption_proof_verifies_end_to_end() {
    // numKeys = 2: one recovery key, one auditor key.
    let recovery = X25519Keypair::new().pubkey();
    let auditor = X25519Keypair::new().pubkey();

    let witness = KeyEncryptionWitness {
        viewing_secret_key: X25519Keypair::new(),
        ephemeral_secret_key: X25519Keypair::new(),
        nullifier_secret: random_bn254_scalar(),
        recipient_keys: vec![recovery, auditor],
        old_state_hash: [0u8; 32],
    };

    let proof_result = witness.prove().expect("proof generation must succeed");

    assert_eq!(proof_result.recipient_ciphertexts.len(), 2);
    // Recipient ciphertexts encrypt the 32-byte viewing secret.
    assert!(proof_result
        .recipient_ciphertexts
        .iter()
        .all(|recipient| recipient.ciphertext.len() == 32));
    // The nullifier ciphertext encrypts the 31-byte nullifier secret.
    assert_eq!(proof_result.nullifier_ciphertext.len(), 31);

    assert!(
        verify_on_host(&proof_result),
        "host Groth16 verification of the key-encryption proof failed",
    );

    // Negative control: a different public input must fail, proving the verifier
    // genuinely binds the proof to our computed public-input hash.
    let mut tampered = proof_result;
    tampered.public_input_hash[0] ^= 1;
    assert!(
        !verify_on_host(&tampered),
        "verification must fail for a tampered public input",
    );
}
