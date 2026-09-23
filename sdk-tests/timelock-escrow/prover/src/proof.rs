use timelock_escrow_program::instructions::{escrow::EscrowProof, withdraw::WithdrawProof};
use zolana_gnark_ffi_prover::CompressedProof;

#[derive(Debug, Clone, Copy)]
pub struct TimelockProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

impl From<TimelockProof> for EscrowProof {
    fn from(proof: TimelockProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

impl From<TimelockProof> for WithdrawProof {
    fn from(proof: TimelockProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}

/// Both timelock circuits are registered without a BSB22 commitment, so the
/// compressed proof carries none.
impl From<CompressedProof> for TimelockProof {
    fn from(proof: CompressedProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}
