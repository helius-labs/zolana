use borsh::{BorshDeserialize, BorshSerialize};

/// A Groth16 proof in its compressed on-curve encoding. Carrying it does not
/// require a verifier, so this stays outside the `verify` module and clients that
/// only build or relay batch updates need no `groth16-solana`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CompressedProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl Default for CompressedProof {
    fn default() -> Self {
        Self {
            a: [0; 32],
            b: [0; 64],
            c: [0; 32],
        }
    }
}
