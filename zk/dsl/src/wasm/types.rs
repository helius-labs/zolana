use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;
use tsify::Tsify;

use crate::{ProofResult, ProverError};

/// A Groth16 proof with its public inputs, as the wasm prover returns it.
#[derive(Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    pub proof: Groth16Proof,
    pub compressed_proof: CompressedGroth16Proof,
    /// The public inputs in order, each a 32-byte big-endian value.
    #[tsify(type = "Uint8Array[]")]
    pub public_inputs: Vec<ByteArray<32>>,
}

impl TryFrom<&ProofResult> for Proof {
    type Error = ProverError;

    fn try_from(result: &ProofResult) -> Result<Self, ProverError> {
        let compressed = result.compressed()?;
        Ok(Self {
            proof: Groth16Proof {
                a: result.proof.a,
                b: result.proof.b,
                c: result.proof.c,
            },
            compressed_proof: CompressedGroth16Proof {
                a: compressed.a,
                b: compressed.b,
                c: compressed.c,
            },
            public_inputs: result
                .public_inputs
                .iter()
                .copied()
                .map(ByteArray::new)
                .collect(),
        })
    }
}

#[derive(Serialize, Deserialize, Tsify)]
pub struct Groth16Proof {
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub a: [u8; 64],
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub b: [u8; 128],
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub c: [u8; 64],
}

#[derive(Serialize, Deserialize, Tsify)]
pub struct CompressedGroth16Proof {
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub a: [u8; 32],
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub b: [u8; 64],
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub c: [u8; 32],
}
