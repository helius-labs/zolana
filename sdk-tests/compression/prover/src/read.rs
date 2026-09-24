use zolana_client::{MerkleProof, NonInclusionProof};
use zolana_gnark_ffi_prover::{decimal, utxo_read_proof_inputs, ProofInputMap};
use zolana_program::compression::CompressedProof;

use crate::{CircuitId, PROVER};

/// The UTXO hash and nullifier are the proofs' leaves, and the roots are the
/// proofs' roots.
#[derive(Debug, Clone)]
pub struct ReadProofInputs {
    pub public_input_hash: [u8; 32],
    pub merkle_proof: MerkleProof,
    pub non_inclusion: NonInclusionProof,
}

impl ReadProofInputs {
    fn proof_inputs(&self) -> ProofInputMap {
        let public = [
            ("Public_PublicInputHash", &self.public_input_hash),
            ("Public_UtxoHash", &self.merkle_proof.leaf),
            ("Public_UtxoRoot", &self.merkle_proof.root),
            ("Public_Nullifier", &self.non_inclusion.leaf),
            ("Public_NullifierRoot", &self.non_inclusion.root),
        ];
        public
            .into_iter()
            .map(|(key, value)| (key.to_string(), vec![decimal(value)]))
            .chain(utxo_read_proof_inputs(
                &self.merkle_proof,
                &self.non_inclusion,
                "Read",
            ))
            .collect()
    }

    pub fn prove(&self) -> zolana_gnark_ffi_prover::Result<CompressedProof> {
        let proof = PROVER
            .prove(CircuitId::Read, &self.proof_inputs())?
            .compress()?;
        Ok(CompressedProof {
            proof_a: proof.proof_a,
            proof_b: proof.proof_b,
            proof_c: proof.proof_c,
        })
    }
}
