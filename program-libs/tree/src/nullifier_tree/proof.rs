use borsh::{BorshDeserialize, BorshSerialize};

use crate::nullifier_tree::error::NullifierTreeError;

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

impl CompressedProof {
    pub fn to_array(&self) -> [u8; 128] {
        let mut result = [0u8; 128];
        result[0..32].copy_from_slice(&self.a);
        result[32..96].copy_from_slice(&self.b);
        result[96..128].copy_from_slice(&self.c);
        result
    }
}

impl TryFrom<&[u8]> for CompressedProof {
    type Error = NullifierTreeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 128 {
            return Err(NullifierTreeError::InvalidProofSize(bytes.len()));
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 64];
        let mut c = [0u8; 32];
        a.copy_from_slice(&bytes[0..32]);
        b.copy_from_slice(&bytes[32..96]);
        c.copy_from_slice(&bytes[96..128]);
        Ok(Self { a, b, c })
    }
}
