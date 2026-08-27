//! Prover-server startup and Groth16 verification against the committed verifying
//! keys. The `prove_and_verify_*` helpers are the infra the transfer step calls
//! once it has built a rail-specific proof result.

use zolana_client::{
    spawn_prover, verify_confidential_transfer_proof, ProverClient, TransferProofResult,
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

pub(crate) fn prove_and_verify_eddsa(result: &TransferProofResult) {
    start_prover();
    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
        .expect("prove transfer-eddsa");
    verify_confidential_transfer_proof(result, &proof).expect("groth16 proof verifies");
}
