//! Prover-server startup and Groth16 verification against the committed verifying
//! keys. The `prove_and_verify_*` helpers are the infra the transfer step calls
//! once it has built a rail-specific proof result.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use zolana_client::{spawn_prover, ProverClient, TransferProofResult};
use zolana_interface::verifying_keys::{
    transfer_confidential_1_1, transfer_confidential_1_2, transfer_confidential_1_8,
    transfer_confidential_2_2, transfer_confidential_2_3, transfer_confidential_3_3,
    transfer_confidential_4_3, transfer_confidential_4_4, transfer_confidential_5_3,
    transfer_confidential_5_4,
};

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

/// The verifying key for the resolved `(n_inputs, n_outputs)` shape. The builder
/// picks the smallest supported shape that fits, so a scenario without a real
/// recipient proves a smaller shape than (2,3); verification must use the key for
/// that same shape, not a fixed one.
fn eddsa_vk(n_inputs: usize, n_outputs: usize) -> &'static Groth16Verifyingkey<'static> {
    match (n_inputs, n_outputs) {
        (1, 1) => &transfer_confidential_1_1::VERIFYINGKEY,
        (1, 2) => &transfer_confidential_1_2::VERIFYINGKEY,
        (1, 8) => &transfer_confidential_1_8::VERIFYINGKEY,
        (2, 2) => &transfer_confidential_2_2::VERIFYINGKEY,
        (2, 3) => &transfer_confidential_2_3::VERIFYINGKEY,
        (3, 3) => &transfer_confidential_3_3::VERIFYINGKEY,
        (4, 3) => &transfer_confidential_4_3::VERIFYINGKEY,
        (4, 4) => &transfer_confidential_4_4::VERIFYINGKEY,
        (5, 3) => &transfer_confidential_5_3::VERIFYINGKEY,
        (5, 4) => &transfer_confidential_5_4::VERIFYINGKEY,
        other => panic!("no eddsa verifying key for shape {other:?}"),
    }
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
        eddsa_vk(result.nullifiers.len(), result.output_hashes.len()),
    )
    .expect("construct verifier");
    verifier.verify().expect("groth16 proof verifies");
}
