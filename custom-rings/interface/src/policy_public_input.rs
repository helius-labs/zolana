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
    /// The sixteen chained elements, audit block then policy tail, the compressed
    /// variant appends the head-map roots to these.
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
            zolana_hasher::primitives::right_align(&self.window_index.to_be_bytes()),
            zolana_hasher::primitives::right_align(&[u8::from(self.approval_required)]),
        ])
    }

    /// `HashChain([audit elements 1..8, policy_hash, state_root, nullifier_root,
    /// entries_tree_id, ring_id, namespace_owner_hash, window_index,
    /// approval_required])`, mirroring the circuit element for element.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }
}

/// The compressed windowed variant, the policy tail followed by the head map's
/// old and new roots, a separate verifying key from the per-record-PDA circuit.
pub struct CompressedPolicyPublicInput<'a> {
    pub policy: CustomRingPolicyPublicInput<'a>,
    /// The head-map root the transition reads, checked equal to the on-chain root.
    pub head_old_root: &'a [u8; 32],
    /// The head-map root the transition writes, the on-chain root advances to it.
    pub head_new_root: &'a [u8; 32],
}

impl CompressedPolicyPublicInput<'_> {
    /// The sixteen policy elements followed by `head_old_root`, `head_new_root`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let policy = self.policy.elements()?;
        let mut chain = [[0u8; 32]; 18];
        chain[..16].copy_from_slice(&policy);
        chain[16] = *self.head_old_root;
        chain[17] = *self.head_new_root;
        create_hash_chain_from_slice(&chain)
    }
}
