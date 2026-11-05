//! Prover-server startup and Groth16 verification against the committed verifying
//! keys. The `prove_and_verify_*` helpers are the infra the transfer step calls
//! once it has built a rail-specific proof result.

use spr_client::{
    verify_confidential_transfer_proof, ProverClient, ProverExt, TransferProofResult,
};

use crate::prover_bootstrap::start_prover;

pub(crate) fn prove_and_verify_eddsa(result: &TransferProofResult) {
    start_prover();
    let proof = ProverClient::local()
        .prove_transfer(&result.inputs)
        .expect("prove transfer-eddsa");
    verify_confidential_transfer_proof(result, &proof).expect("groth16 proof verifies");
}
