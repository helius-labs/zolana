use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::right_align, HasherError,
};
use zolana_interface::tree_slot::tree_id_field;

use crate::base_public_input::CustomRingBasePublicInput;

/// Binds audited transaction openings to the pinned rules, list roots and
/// amount controls.
pub struct CustomRingPolicyPublicInput<'a> {
    pub audit: CustomRingBasePublicInput<'a>,
    pub policy_hash: &'a [u8; 32],
    pub state_root: &'a [u8; 32],
    pub nullifier_root: &'a [u8; 32],
    /// Raw id of the entries tree, a wrong id derives absent addresses.
    pub entries_tree_id: u16,
    /// `hash_bytes` of the ring program id, the ring a change output stays in.
    pub ring_id: &'a [u8; 32],
    /// The owner of every spend record, no other slot may open to it.
    pub namespace_owner_hash: &'a [u8; 32],
    /// Fixed-window index, zero for per-transfer limits and delegate moves.
    pub window_index: u64,
    pub approval_required: bool,
}

impl CustomRingPolicyPublicInput<'_> {
    /// The audit prefix and policy tail share one circuit-defined field order.
    fn elements(&self) -> Result<[[u8; 32]; 16], HasherError> {
        let audit = self.audit.elements()?;
        Ok([
            audit[0],
            audit[1],
            audit[2],
            audit[3],
            audit[4],
            audit[5],
            audit[6],
            audit[7],
            *self.policy_hash,
            *self.state_root,
            *self.nullifier_root,
            tree_id_field(self.entries_tree_id),
            *self.ring_id,
            *self.namespace_owner_hash,
            right_align(&self.window_index.to_be_bytes()),
            right_align(&[u8::from(self.approval_required)]),
        ])
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }
}

/// Extends policy verification with the current and successor spend-history
/// roots.
pub struct CompressedPolicyPublicInput<'a> {
    pub counters_disclosure_hash: &'a [u8; 32],
    pub policy: CustomRingPolicyPublicInput<'a>,
    /// The head-map root the transition reads, checked equal to the on-chain root.
    pub head_old_root: &'a [u8; 32],
    /// The head-map root the transition writes, the on-chain root advances to it.
    pub head_new_root: &'a [u8; 32],
}

impl CompressedPolicyPublicInput<'_> {
    /// Root order must match the compressed policy circuit.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let policy = self.policy.elements()?;
        let mut chain = [[0u8; 32]; 19];
        chain[..16].copy_from_slice(&policy);
        chain[16] = *self.head_old_root;
        chain[17] = *self.head_new_root;
        chain[18] = *self.counters_disclosure_hash;
        create_hash_chain_from_slice(&chain)
    }
}
