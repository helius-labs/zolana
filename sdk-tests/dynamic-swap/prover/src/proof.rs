use zolana_gnark_ffi_prover::CompressedProof;

// Compressed, negated Groth16 proof ready for the on-chain verifier. Both
// dynamic-swap circuits are standard Groth16 (no BSB22 commitment), so the
// verifier uses `Groth16Verifier::new`; the SDK reads only `proof_a`/`proof_b`/
// `proof_c` into the program's `*Proof` instruction-data types.
#[derive(Debug, Clone, Copy)]
pub struct OrderProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

impl From<CompressedProof> for OrderProof {
    fn from(proof: CompressedProof) -> Self {
        Self {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        }
    }
}
