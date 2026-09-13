use borsh::{BorshDeserialize, BorshSerialize};

/// Vanilla Groth16 proof of a nullifier-tree batch update: `a(32) || b(128) ||
/// c(32)` -- 192 bytes. `a` and `c` are compressed G1 points, `b` is the raw
/// big-endian G2 point so the program skips the G2 decompression syscall, the
/// same encoding as `TransactProof` and `MergeProof`.
///
/// Carrying it does not require a verifier, so this stays outside the `verify`
/// module and clients that only build or relay batch updates need no
/// `groth16-solana`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct NullifierTreeProof {
    pub a: [u8; 32],
    pub b: [u8; 128],
    pub c: [u8; 32],
}

impl Default for NullifierTreeProof {
    fn default() -> Self {
        Self {
            a: [0; 32],
            b: [0; 128],
            c: [0; 32],
        }
    }
}
