//! Prover-server startup and Groth16 verification against the committed verifying
//! keys. The `prove_and_verify_*` helpers are the infra the transfer step calls
//! once it has built a rail-specific proof result.

use groth16_solana::groth16::Groth16Verifier;
use zolana_client::{spawn_prover, ProverClient, TransferP256ProofResult, TransferProofResult};
use zolana_interface::verifying_keys::{transfer_2_3, transfer_p256_2_3};

pub(crate) fn start_prover() {
    // Point the prover at the in-repo proving keys (once, to avoid a concurrent
    // set_var race across the non-serial scenarios).
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

pub(crate) fn prove_and_verify_p256(result: &TransferP256ProofResult) {
    start_prover();
    let proof = ProverClient::local()
        .prove_transfer_p256(&result.inputs)
        .expect("prove transfer");
    let commitments = proof
        .commitment
        .expect("P256 transfer proof must carry a commitment");
    let public_inputs: [[u8; 32]; 1] = [result.public_input_hash];
    let mut verifier = Groth16Verifier::new_with_commitment(
        &proof.a,
        &proof.b,
        &proof.c,
        &commitments.commitment,
        &commitments.commitment_pok,
        &public_inputs,
        &transfer_p256_2_3::VERIFYINGKEY,
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}

pub(crate) fn prove_and_verify_eddsa(result: &TransferProofResult) {
    start_prover();
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
