//! Supported proof shapes and verifying-key selection (task M2.6).
//!
//! These shape sets MUST stay in sync with the circuits `squads-prover`
//! registers (`rings/squads/prover/circuits/main.go` and its `CircuitId`). A
//! shape the prover can produce a proof for but the program cannot select a VK
//! for (or vice versa) silently breaks verification, so the lists are a single
//! logical source of truth.

use groth16_solana::groth16::Groth16Verifyingkey;
use zolana_squads_interface::{
    error::SquadsRingError,
    verifying_keys::{key_encryption_1, key_encryption_2, key_encryption_3, ring_1_1, ring_2_2},
};

/// Supported ring circuit shapes as `(n_inputs, n_outputs)`.
/// `(1, 1)` = withdrawal, `(2, 2)` = transfer.
pub const RING_SUPPORTED_SHAPES: [(u8, u8); 2] = [(1, 1), (2, 2)];

/// Supported key-encryption recipient counts (recovery + auditor keys).
pub const KEY_ENCRYPTION_SUPPORTED_KEYS: [u8; 3] = [1, 2, 3];

/// Select the ring verifying key for the `(n_inputs, n_outputs)` shape, returning
/// an error for an unsupported shape.
#[inline(always)]
pub fn select_ring_vk(
    n_inputs: u8,
    n_outputs: u8,
) -> Result<&'static Groth16Verifyingkey<'static>, SquadsRingError> {
    match (n_inputs, n_outputs) {
        (1, 1) => Ok(&ring_1_1::VERIFYINGKEY),
        (2, 2) => Ok(&ring_2_2::VERIFYINGKEY),
        _ => Err(SquadsRingError::RingProofVerificationFailed),
    }
}

/// Select the key-encryption verifying key for `num_keys` recipient keys,
/// returning an error for an unsupported count.
#[inline(always)]
pub fn select_key_encryption_vk(
    num_keys: u8,
) -> Result<&'static Groth16Verifyingkey<'static>, SquadsRingError> {
    match num_keys {
        1 => Ok(&key_encryption_1::VERIFYINGKEY),
        2 => Ok(&key_encryption_2::VERIFYINGKEY),
        3 => Ok(&key_encryption_3::VERIFYINGKEY),
        _ => Err(SquadsRingError::KeyEncryptionProofVerificationFailed),
    }
}
