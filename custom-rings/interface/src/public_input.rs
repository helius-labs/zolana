use zolana_hasher::{hash_chain::create_hash_chain_from_slice, HasherError};

use crate::audit::AuditPublicInput;

/// Inputs of the ring circuit's single public input, the tail recomputed
/// on-chain to bind the proof to one rule table and one pair of tree roots.
pub struct CustomRingPublicInput<'a> {
    pub audit: AuditPublicInput<'a>,
    pub policy_hash: &'a [u8; 32],
    pub state_root: &'a [u8; 32],
    pub nullifier_root: &'a [u8; 32],
}

impl CustomRingPublicInput<'_> {
    /// `HashChain([audit elements 1..8, policy_hash, state_root,
    /// nullifier_root])`, mirroring the circuit element for element.
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
        ])
    }
}
