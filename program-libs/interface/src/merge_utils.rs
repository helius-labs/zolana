//! Canonical `no_std`-compatible fixed-length byte commitments shared by the
//! merge program, SDK, and circuits.

use spr_hasher::{primitives::hash_bytes, HasherError};

/// Fixed-length ciphertext proof-input hash.
pub fn ciphertext_hash<const N: usize>(ciphertext: &[u8; N]) -> Result<[u8; 32], HasherError> {
    hash_bytes(ciphertext)
}
