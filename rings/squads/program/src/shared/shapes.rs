//! Supported proof shapes and verifying-key selection.
//!
//! These shape sets MUST stay in sync with the Go prover's lazy key manager:
//! `prover/server/prover/common/lazy_key_manager.go` -- `zoneSupportedShapes`
//! (zone `(nInputs, nOutputs)` pairs) and `keyEncryptionSupportedKeys`
//! (key-encryption recipient counts), plus `lazy_key_manager_squads_fold.go`
//! for the folds. A shape the prover can produce a proof for but the program
//! cannot select a VK for (or vice versa) silently breaks verification, so the
//! two lists are a single logical source of truth.

use groth16_solana::groth16::Groth16Verifyingkey;
use zolana_squads_interface::{
    error::SquadsZoneError,
    verifying_keys::{
        key_encryption_1, key_encryption_2, key_encryption_3, key_encryption_fold_3_l2,
        key_encryption_fold_3_l3, zone_1_1, zone_2_2, zone_fold_2_2_l2, zone_fold_2_2_l3,
    },
};

/// Supported zone circuit shapes as `(n_inputs, n_outputs)`.
/// `(1, 1)` = withdrawal, `(2, 2)` = transfer.
pub const ZONE_SUPPORTED_SHAPES: [(u8, u8); 2] = [(1, 1), (2, 2)];

/// Supported key-encryption recipient counts (recovery + auditor keys).
pub const KEY_ENCRYPTION_SUPPORTED_KEYS: [u8; 3] = [1, 2, 3];

/// Recipients per leg of a folded key-encryption proof. The widest count with
/// an unfolded key, so a fold covers the most recipients per verification.
pub const KEY_ENCRYPTION_FOLD_KEYS_PER_LEG: u8 = 3;

pub const KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS: [u8; 2] = [2, 3];

/// Recipient counts a folded key-encryption proof covers.
///
/// A fold's public input is the chain a single circuit over the whole set would
/// expose, so `KeyEncryptionProof` composes it the same way and only the
/// verifying key differs.
pub const KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS: [u8; 2] = [
    KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS[0] * KEY_ENCRYPTION_FOLD_KEYS_PER_LEG,
    KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS[1] * KEY_ENCRYPTION_FOLD_KEYS_PER_LEG,
];

/// Leg shapes a zone fold covers. Only the transfer shape folds, a withdrawal
/// already spends the whole balance.
pub const ZONE_FOLD_SUPPORTED_SHAPES: [(u8, u8); 1] = [(2, 2)];

pub const ZONE_FOLD_SUPPORTED_LEGS: [u8; 2] = [2, 3];

/// The widest supported leg count. `ZONE_FOLD_SUPPORTED_LEGS` is ascending, so
/// the last entry is the maximum.
pub const ZONE_FOLD_MAX_LEGS: u8 = ZONE_FOLD_SUPPORTED_LEGS[ZONE_FOLD_SUPPORTED_LEGS.len() - 1];

/// The zone shape an operation names, checked against the instruction data the
/// SPP proof is built from.
///
/// The operation is the single source of the shape. SPP picks its own circuit
/// from `input_contexts.len()` and the output count, so both proofs describe one
/// shape only while these agree.
#[inline(always)]
pub fn operation_shape(
    is_transfer: bool,
    input_contexts: usize,
    output_utxo_hashes: usize,
) -> Result<(u8, u8), SquadsZoneError> {
    let (n_inputs, n_outputs) = if is_transfer { (2u8, 2u8) } else { (1u8, 1u8) };
    if input_contexts != usize::from(n_inputs) || output_utxo_hashes != usize::from(n_outputs) {
        return Err(SquadsZoneError::ProofShapeMismatch);
    }
    Ok((n_inputs, n_outputs))
}

#[inline(always)]
pub fn select_zone_vk(
    n_inputs: u8,
    n_outputs: u8,
) -> Result<&'static Groth16Verifyingkey<'static>, SquadsZoneError> {
    match (n_inputs, n_outputs) {
        (1, 1) => Ok(&zone_1_1::VERIFYINGKEY),
        (2, 2) => Ok(&zone_2_2::VERIFYINGKEY),
        _ => Err(SquadsZoneError::UnsupportedProofShape),
    }
}

/// The leg verifying key is a compile-time constant of the fold circuit, so
/// the selected key alone names the shape a fold proved.
#[inline(always)]
pub fn select_zone_fold_vk(
    n_inputs: u8,
    n_outputs: u8,
    legs: u8,
) -> Result<&'static Groth16Verifyingkey<'static>, SquadsZoneError> {
    match (n_inputs, n_outputs, legs) {
        (2, 2, 2) => Ok(&zone_fold_2_2_l2::VERIFYINGKEY),
        (2, 2, 3) => Ok(&zone_fold_2_2_l3::VERIFYINGKEY),
        _ => Err(SquadsZoneError::UnsupportedProofShape),
    }
}

/// Counts above the unfolded set resolve to a fold key, which proves the same
/// statement over a wider set.
#[inline(always)]
pub fn select_key_encryption_vk(
    num_keys: u8,
) -> Result<&'static Groth16Verifyingkey<'static>, SquadsZoneError> {
    match num_keys {
        1 => Ok(&key_encryption_1::VERIFYINGKEY),
        2 => Ok(&key_encryption_2::VERIFYINGKEY),
        3 => Ok(&key_encryption_3::VERIFYINGKEY),
        6 => Ok(&key_encryption_fold_3_l2::VERIFYINGKEY),
        9 => Ok(&key_encryption_fold_3_l3::VERIFYINGKEY),
        _ => Err(SquadsZoneError::UnsupportedKeyCount),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Selector and catalogue must agree in both directions. A count the prover
    /// can produce but the program cannot resolve a key for fails verification
    /// with no useful signal, and a key with no supported count is dead weight.
    #[test]
    fn key_encryption_support_and_keys_agree() {
        for keys in KEY_ENCRYPTION_SUPPORTED_KEYS
            .iter()
            .chain(KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS.iter())
        {
            assert!(
                select_key_encryption_vk(*keys).is_ok(),
                "{keys} keys are supported but have no verifying key",
            );
        }
        for keys in 0u8..=32 {
            let supported = KEY_ENCRYPTION_SUPPORTED_KEYS.contains(&keys)
                || KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS.contains(&keys);
            assert_eq!(
                supported,
                select_key_encryption_vk(keys) != Err(SquadsZoneError::UnsupportedKeyCount),
                "{keys} keys resolve a key the catalogue does not list",
            );
        }
    }

    /// Every spend path takes the shape from the operation instead of the
    /// instruction data vector lengths. That is only sound while one output
    /// count names one shape.
    #[test]
    fn output_count_determines_one_zone_shape() {
        for (_, n_outputs) in ZONE_SUPPORTED_SHAPES {
            let matching = ZONE_SUPPORTED_SHAPES
                .iter()
                .filter(|(_, outputs)| *outputs == n_outputs)
                .count();
            assert_eq!(matching, 1, "{n_outputs} outputs name more than one shape");
        }

        // A shape outside the catalogue resolves no key.
        assert_eq!(
            select_zone_vk(2, 1),
            Err(SquadsZoneError::UnsupportedProofShape)
        );

        // Both operations resolve to a catalogued shape.
        assert_eq!(operation_shape(true, 2, 2), Ok((2, 2)));
        assert_eq!(operation_shape(false, 1, 1), Ok((1, 1)));
        for (n_inputs, n_outputs) in [operation_shape(true, 2, 2), operation_shape(false, 1, 1)]
            .into_iter()
            .map(|shape| shape.expect("supported shape"))
        {
            assert!(ZONE_SUPPORTED_SHAPES.contains(&(n_inputs, n_outputs)));
        }

        // Instruction data that names a different shape than the operation is
        // rejected, so the zone proof and the SPP proof cannot disagree.
        for (is_transfer, inputs, outputs) in
            [(true, 1, 2), (true, 2, 1), (false, 2, 1), (false, 1, 2)]
        {
            assert_eq!(
                operation_shape(is_transfer, inputs, outputs),
                Err(SquadsZoneError::ProofShapeMismatch)
            );
        }
    }

    #[test]
    fn zone_fold_support_and_keys_agree() {
        for (n_inputs, n_outputs) in ZONE_FOLD_SUPPORTED_SHAPES {
            for legs in ZONE_FOLD_SUPPORTED_LEGS {
                assert!(
                    select_zone_fold_vk(n_inputs, n_outputs, legs).is_ok(),
                    "{legs} {n_inputs}x{n_outputs} legs are supported but have no verifying key",
                );
            }
        }
        for n_inputs in 0u8..=4 {
            for n_outputs in 0u8..=4 {
                for legs in 0u8..=4 {
                    let supported = ZONE_FOLD_SUPPORTED_SHAPES.contains(&(n_inputs, n_outputs))
                        && ZONE_FOLD_SUPPORTED_LEGS.contains(&legs);
                    assert_eq!(
                        supported,
                        select_zone_fold_vk(n_inputs, n_outputs, legs)
                            != Err(SquadsZoneError::UnsupportedProofShape),
                        "{legs} {n_inputs}x{n_outputs} legs resolve a key the catalogue does not list",
                    );
                }
            }
        }
    }

    /// A fold's recipient count must not collide with an unfolded one, or the
    /// selector would silently pick the wrong circuit's key.
    #[test]
    fn folded_and_unfolded_key_counts_are_disjoint() {
        for keys in KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS {
            assert!(
                !KEY_ENCRYPTION_SUPPORTED_KEYS.contains(&keys),
                "{keys} keys resolve to both a fold and an unfolded key",
            );
        }
    }
}
