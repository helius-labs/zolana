use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::right_align, HasherError,
};
use zolana_interface::tree_slot::{populated_tree_slots_hash_chain, tree_id_field, TreeSlot};

use crate::base_public_input::CustomRingBasePublicInput;

const AUDIT_LEN: usize = 11;
const POLICY_LEN: usize = 20;
/// The folded audit prefix and policy hash, then the tail without the tree commitment.
pub const POLICY_INDEXED_INPUTS: usize = POLICY_LEN - AUDIT_LEN - 1;

/// Binds audited transaction openings to the pinned rules, the member registry roots and
/// outflow limits.
pub struct CustomRingPolicyPublicInput<'a> {
    pub audit: CustomRingBasePublicInput<'a>,
    pub policy_hash: &'a [u8; 32],
    /// Populated prefix of the trees the transaction reads.
    pub tree_slots: &'a [TreeSlot],
    /// Raw id of the address tree.
    pub address_tree_id: u16,
    /// `hash_bytes` of the ring program id, the ring a change output stays in.
    pub ring_id: &'a [u8; 32],
    /// The ring's namespace owner, no transfer slot may open to it.
    pub namespace_owner_hash: &'a [u8; 32],
    /// Set when an outflow exceeds a limit's cosign threshold, false on the delegate rail.
    pub approval_required: bool,
    /// Every live output owner's record must escrow the key the output uses.
    pub key_escrow: bool,
    /// The ring's own registry root every subject opens under.
    pub member_registry_root: &'a [u8; 32],
    /// The curator registry root the sources name, zero without one.
    pub foreign_root: &'a [u8; 32],
}

impl CustomRingPolicyPublicInput<'_> {
    /// The audit prefix and policy tail share one circuit-defined field order.
    fn elements(&self) -> Result<[[u8; 32]; POLICY_LEN], HasherError> {
        let audit = self.audit.elements()?;
        let mut elements = [[0u8; 32]; POLICY_LEN];
        elements[..AUDIT_LEN].copy_from_slice(&audit);
        elements[AUDIT_LEN..].copy_from_slice(&[
            *self.policy_hash,
            populated_tree_slots_hash_chain(self.tree_slots)?,
            tree_id_field(self.address_tree_id),
            *self.ring_id,
            *self.namespace_owner_hash,
            right_align(&[u8::from(self.approval_required)]),
            right_align(&[u8::from(self.key_escrow)]),
            *self.member_registry_root,
            *self.foreign_root,
        ]);
        Ok(elements)
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }

    pub fn indexed_inputs(&self) -> Result<[[u8; 32]; POLICY_INDEXED_INPUTS], HasherError> {
        let elements = self.elements()?;
        let mut indexed = [[0u8; 32]; POLICY_INDEXED_INPUTS];
        // The folded prefix ends immediately before the tree commitment.
        indexed[0] = create_hash_chain_from_slice(&elements[..AUDIT_LEN + 1])?;
        indexed[1..].copy_from_slice(&elements[AUDIT_LEN + 2..]);
        Ok(indexed)
    }
}

/// The escrow flag and the registry root a deposit binds, zero when escrow is off.
pub(crate) fn key_escrow_elements(root: Option<&[u8; 32]>) -> [[u8; 32]; 2] {
    [
        right_align(&[u8::from(root.is_some())]),
        root.copied().unwrap_or_default(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escrow_off_publishes_a_zero_flag_and_a_zero_root() {
        assert_eq!(key_escrow_elements(None), [[0u8; 32]; 2]);
        let root = [9u8; 32];
        assert_eq!(key_escrow_elements(Some(&root)), [right_align(&[1]), root]);
    }
}
