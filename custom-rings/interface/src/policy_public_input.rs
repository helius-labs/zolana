use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::right_align, HasherError,
};
use zolana_interface::tree_slot::{populated_tree_slots_hash_chain, tree_id_field, TreeSlot};

use crate::base_public_input::CustomRingBasePublicInput;
use zolana_ring_policy::ANSWER_SLOTS;

const AUDIT_LEN: usize = 11;
const POLICY_PREFIX_LEN: usize = 21;
const POLICY_LEN: usize = POLICY_PREFIX_LEN + ANSWER_SLOTS;
const COMPRESSED_POLICY_LEN: usize = POLICY_LEN + 1;
const REVOCATION_TREE_INDEX_BITS: usize = 3;
const _: () = assert!(ANSWER_SLOTS * REVOCATION_TREE_INDEX_BITS <= u64::BITS as usize);

/// Binds audited transaction openings to the pinned rules, list roots and
/// amount controls.
pub struct CustomRingPolicyPublicInput<'a> {
    pub audit: CustomRingBasePublicInput<'a>,
    pub policy_hash: &'a [u8; 32],
    /// Populated prefix, the proof reads list facts from these trees only.
    pub tree_slots: &'a [TreeSlot],
    /// Raw id of the address tree, a wrong id derives absent addresses.
    pub address_tree_id: u16,
    /// `hash_bytes` of the ring program id, the ring a change output stays in.
    pub ring_id: &'a [u8; 32],
    /// The owner of every spend record, no other slot may open to it.
    pub namespace_owner_hash: &'a [u8; 32],
    /// Fixed-window index, zero for per-transfer limits and delegate moves.
    pub window_index: u64,
    pub approval_required: bool,
    /// Present exactly when output nullifier keys must be enrolled under it.
    pub key_registry_root: Option<&'a [u8; 32]>,
    /// Per fact slot, the index into `tree_slots` its revocation target lives in.
    pub revocation_tree_indexes: &'a [u8; ANSWER_SLOTS],
    pub revocation_targets: &'a [[u8; 32]; ANSWER_SLOTS],
}

impl CustomRingPolicyPublicInput<'_> {
    /// The audit prefix and policy tail share one circuit-defined field order.
    fn elements(&self) -> Result<[[u8; 32]; POLICY_LEN], HasherError> {
        let audit = self.audit.elements()?;
        let [key_escrow, key_registry_root] = key_escrow_elements(self.key_registry_root);
        let mut elements = [[0u8; 32]; POLICY_LEN];
        elements[..AUDIT_LEN].copy_from_slice(&audit);
        elements[AUDIT_LEN..POLICY_PREFIX_LEN].copy_from_slice(&[
            *self.policy_hash,
            populated_tree_slots_hash_chain(self.tree_slots)?,
            tree_id_field(self.address_tree_id),
            *self.ring_id,
            *self.namespace_owner_hash,
            right_align(&self.window_index.to_be_bytes()),
            right_align(&[u8::from(self.approval_required)]),
            key_escrow,
            key_registry_root,
            pack_revocation_tree_indexes(self.revocation_tree_indexes)?,
        ]);
        elements[POLICY_PREFIX_LEN..].copy_from_slice(self.revocation_targets);
        Ok(elements)
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }
}

/// The escrow flag and the registry root, zero when escrow is off.
pub(crate) fn key_escrow_elements(root: Option<&[u8; 32]>) -> [[u8; 32]; 2] {
    [
        right_align(&[u8::from(root.is_some())]),
        root.copied().unwrap_or_default(),
    ]
}

/// `Σ index_i · 8^i`, an index of 8 or more would alias its neighbour.
fn pack_revocation_tree_indexes(indexes: &[u8; ANSWER_SLOTS]) -> Result<[u8; 32], HasherError> {
    let packed = indexes
        .iter()
        .enumerate()
        .try_fold(0u64, |packed, (slot, &index)| {
            if index >> REVOCATION_TREE_INDEX_BITS != 0 {
                return Err(HasherError::IntegerOverflow);
            }
            Ok(packed | u64::from(index) << (slot * REVOCATION_TREE_INDEX_BITS))
        })?;
    Ok(right_align(&packed.to_be_bytes()))
}

pub struct CompressedPolicyPublicInput<'a> {
    pub counters_disclosure_hash: &'a [u8; 32],
    pub policy: CustomRingPolicyPublicInput<'a>,
}

impl CompressedPolicyPublicInput<'_> {
    /// Field order must match the compressed policy circuit.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let policy = self.policy.elements()?;
        let mut chain = [[0u8; 32]; COMPRESSED_POLICY_LEN];
        chain[..POLICY_LEN].copy_from_slice(&policy);
        chain[POLICY_LEN] = *self.counters_disclosure_hash;
        create_hash_chain_from_slice(&chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_tree_indexes_pack_three_bits_per_slot() {
        let mut indexes = [0u8; ANSWER_SLOTS];
        indexes[0] = 1;
        indexes[1] = 4;
        indexes[ANSWER_SLOTS - 1] = 7;
        let expected = 1 | 4 << 3 | 7u64 << (3 * (ANSWER_SLOTS - 1));
        assert_eq!(
            pack_revocation_tree_indexes(&indexes),
            Ok(right_align(&expected.to_be_bytes()))
        );
        indexes[2] = 8;
        assert_eq!(
            pack_revocation_tree_indexes(&indexes),
            Err(HasherError::IntegerOverflow)
        );
    }

    #[test]
    fn escrow_off_publishes_a_zero_flag_and_a_zero_root() {
        assert_eq!(key_escrow_elements(None), [[0u8; 32]; 2]);
        let root = [9u8; 32];
        assert_eq!(key_escrow_elements(Some(&root)), [right_align(&[1]), root]);
    }
}
