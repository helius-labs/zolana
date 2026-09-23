use compression_example_program::instructions::read::ReadProof;
use groth16_solana::groth16::negate_g1_be;
use num_bigint::BigUint;
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g2_compress_be};

use crate::ffi::{self, WitnessMap};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("ffi error: {0}")]
    Ffi(#[from] ffi::Error),
    #[error("compress G1 failed: {0}")]
    CompressG1(String),
    #[error("compress G2 failed: {0}")]
    CompressG2(String),
}

#[derive(Debug, Clone)]
pub struct ReadProofInputs {
    pub public_input_hash: [u8; 32],
    pub utxo_hash: [u8; 32],
    pub utxo_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub state_path_elements: Vec<[u8; 32]>,
    pub state_path_index: u64,
    pub nullifier_low_value: [u8; 32],
    pub nullifier_next_value: [u8; 32],
    pub nullifier_low_path_elements: Vec<[u8; 32]>,
    pub nullifier_low_path_index: u64,
}

fn decimal(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}

impl ReadProofInputs {
    fn witness(&self) -> WitnessMap {
        let scalars = [
            ("Public_PublicInputHash", decimal(&self.public_input_hash)),
            ("Public_UtxoHash", decimal(&self.utxo_hash)),
            ("Public_UtxoRoot", decimal(&self.utxo_root)),
            ("Public_Nullifier", decimal(&self.nullifier)),
            ("Public_NullifierRoot", decimal(&self.nullifier_root)),
            ("StatePathIndex", self.state_path_index.to_string()),
            ("NullifierLowValue", decimal(&self.nullifier_low_value)),
            ("NullifierNextValue", decimal(&self.nullifier_next_value)),
            (
                "NullifierLowPathIndex",
                self.nullifier_low_path_index.to_string(),
            ),
        ];
        let paths = [
            ("StatePathElements", &self.state_path_elements),
            (
                "NullifierLowPathElements",
                &self.nullifier_low_path_elements,
            ),
        ];
        scalars
            .into_iter()
            .map(|(key, value)| (key.to_string(), vec![value]))
            .chain(
                paths
                    .into_iter()
                    .map(|(key, path)| (key.to_string(), path.iter().map(decimal).collect())),
            )
            .collect()
    }

    pub fn prove(&self) -> Result<ReadProof, ProofError> {
        let out = ffi::prove(&self.witness())?;
        let proof_a = alt_bn128_g1_compress_be(&negate_g1_be(&out.proof_a))
            .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
        let proof_b = alt_bn128_g2_compress_be(&out.proof_b)
            .map_err(|e| ProofError::CompressG2(format!("{e:?}")))?;
        let proof_c = alt_bn128_g1_compress_be(&out.proof_c)
            .map_err(|e| ProofError::CompressG1(format!("{e:?}")))?;
        Ok(ReadProof {
            proof_a,
            proof_b,
            proof_c,
        })
    }
}
