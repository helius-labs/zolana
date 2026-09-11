use zolana_hasher::{hash_chain::create_hash_chain_from_slice, HasherError};
use zolana_interface::tree_slot::tree_id_field;

use crate::base_public_input::CustomRingBasePublicInput;

/// Inputs of the ring circuit's single public input, the tail recomputed
/// on-chain to bind the proof to one rule table, one pair of tree roots and
/// one spend window.
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
    /// `slot / window_slots`, zero without velocity.
    pub window_index: u64,
    pub approval_required: bool,
}

impl CustomRingPolicyPublicInput<'_> {
    /// `HashChain([audit elements 1..8, policy_hash, state_root, nullifier_root,
    /// entries_tree_id, ring_id, namespace_owner_hash, window_index,
    /// approval_required])`, mirroring the circuit element for element.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let audit = self.audit.elements()?;
        create_hash_chain_from_slice(&[
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
            zolana_hasher::primitives::right_align(&self.window_index.to_be_bytes()),
            zolana_hasher::primitives::right_align(&[u8::from(self.approval_required)]),
        ])
    }
}
