//! Fixed-length ciphertext commitments shared by the program and SDK.

use zolana_hasher::{primitives::hash_bytes, HasherError};

/// Commits the complete ciphertext to the proof's public inputs.
pub fn ciphertext_hash<const N: usize>(ciphertext: &[u8; N]) -> Result<[u8; 32], HasherError> {
    hash_bytes(ciphertext)
}
