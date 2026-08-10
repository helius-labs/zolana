//! The shapes the zone circuits are compiled for, and the domain separator a
//! proposal commitment binds.
//!
//! The program, the SDK, and the Go lazy key managers
//! (`prover/server/prover/common/lazy_key_manager.go` and
//! `lazy_key_manager_squads_fold.go`) must select the same set. A shape the
//! prover can produce a proof for but the program cannot resolve a verifying key
//! for fails verification with no useful signal, so the table lives here once.

/// Supported zone circuit shapes as `(n_inputs, n_outputs)`.
/// `(1, 1)` is a withdrawal and `(2, 2)` is a transfer.
pub const ZONE_SUPPORTED_SHAPES: [(u8, u8); 2] = [(1, 1), (2, 2)];

/// Supported key-encryption recipient counts (recovery plus auditor keys).
pub const KEY_ENCRYPTION_SUPPORTED_KEYS: [u8; 3] = [1, 2, 3];

/// Recipients per leg of a folded key-encryption proof. The widest count with an
/// unfolded key, so a fold covers the most recipients per verification.
pub const KEY_ENCRYPTION_FOLD_KEYS_PER_LEG: u8 = 3;

/// Leg counts a folded key-encryption proof is compiled for.
pub const KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS: [u8; 2] = [2, 3];

/// Recipient counts a folded key-encryption proof covers.
///
/// A fold's public input is the chain a single circuit over the whole set would
/// expose, so the proof composes it the same way and only the verifying key
/// differs.
pub const KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS: [u8; 2] = [
    KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS[0] * KEY_ENCRYPTION_FOLD_KEYS_PER_LEG,
    KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS[1] * KEY_ENCRYPTION_FOLD_KEYS_PER_LEG,
];

/// Leg shapes a zone fold covers. Only the transfer shape folds, because a
/// withdrawal already spends the whole balance.
pub const ZONE_FOLD_SUPPORTED_SHAPES: [(u8, u8); 1] = [(2, 2)];

/// Leg counts a zone fold is compiled for.
pub const ZONE_FOLD_SUPPORTED_LEGS: [u8; 2] = [2, 3];

/// The widest supported leg count. [`ZONE_FOLD_SUPPORTED_LEGS`] is ascending, so
/// the last entry is the maximum.
pub const ZONE_FOLD_MAX_LEGS: u8 = ZONE_FOLD_SUPPORTED_LEGS[ZONE_FOLD_SUPPORTED_LEGS.len() - 1];

/// Domain separator for the public asset and destination binding of a v2
/// proposal commitment.
pub const PROPOSAL_V2_DOMAIN: &[u8] = b"ZOLANA/SQUADS/PROPOSAL/V2";

/// The operation a proposal commits to. The discriminant is the value the
/// commitment absorbs, so renumbering it changes every stored proposal hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProposalOperation {
    Withdrawal = 1,
    Transfer = 2,
}

impl ProposalOperation {
    /// The operation as the commitment absorbs it: the discriminant in the last
    /// byte of a field element.
    pub const fn field(self) -> [u8; 32] {
        let mut fe = [0u8; 32];
        fe[31] = self as u8;
        fe
    }
}

/// Right-align a domain label in a field element. The label must be at most 32
/// bytes, which every constant in this module satisfies.
pub fn domain_field(label: &[u8]) -> [u8; 32] {
    let mut fe = [0u8; 32];
    let start = fe.len().saturating_sub(label.len());
    fe[start..].copy_from_slice(label);
    fe
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folded recipient count must not collide with an unfolded one, or a
    /// selector would silently pick the wrong circuit's key.
    #[test]
    fn folded_and_unfolded_key_counts_are_disjoint() {
        for keys in KEY_ENCRYPTION_FOLD_SUPPORTED_KEYS {
            assert!(!KEY_ENCRYPTION_SUPPORTED_KEYS.contains(&keys));
        }
    }

    /// `transact` takes the shape from the operation rather than the instruction
    /// data vector lengths, which is only sound while one output count names one
    /// shape.
    #[test]
    fn output_count_determines_one_zone_shape() {
        for (_, n_outputs) in ZONE_SUPPORTED_SHAPES {
            let matching = ZONE_SUPPORTED_SHAPES
                .iter()
                .filter(|(_, outputs)| *outputs == n_outputs)
                .count();
            assert_eq!(matching, 1, "{n_outputs} outputs name more than one shape");
        }
    }

    #[test]
    fn proposal_operation_field_carries_the_discriminant() {
        assert_eq!(ProposalOperation::Withdrawal.field()[31], 1);
        assert_eq!(ProposalOperation::Transfer.field()[31], 2);
        assert_eq!(ProposalOperation::Transfer.field()[..31], [0u8; 31]);
    }

    #[test]
    fn domain_field_right_aligns_the_label() {
        let field = domain_field(PROPOSAL_V2_DOMAIN);
        assert_eq!(&field[32 - PROPOSAL_V2_DOMAIN.len()..], PROPOSAL_V2_DOMAIN);
        assert_eq!(&field[..32 - PROPOSAL_V2_DOMAIN.len()], &[0u8; 7]);
    }
}
