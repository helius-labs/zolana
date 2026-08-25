use zolana_hasher::{hash_chain::create_hash_chain_from_slice, HasherError};
use zolana_ring_policy::{Policy, RecordKind, Rule, Subject};

use crate::audit::AuditPublicInput;

/// The table hash is pinned at `create_policy`, a drifted build fails every
/// mutation closed.
pub const POLICY: Policy = Policy::builder()
    .rule_if(
        cfg!(feature = "allowlist"),
        Rule::require(Subject::OutputOwner, RecordKind::Allow),
    )
    .rule_if(
        cfg!(feature = "allowlist"),
        Rule::require(Subject::Sender, RecordKind::Allow),
    )
    .rule_if(
        cfg!(feature = "blocklist"),
        Rule::forbid(Subject::OutputOwner, RecordKind::Block),
    )
    .rule_if(
        cfg!(feature = "freeze"),
        Rule::forbid(Subject::Sender, RecordKind::Frozen),
    )
    .build();

/// Inputs of the ring circuit's single public input, the tail recomputed
/// on-chain to bind the proof to one rule table and one pair of tree roots.
pub struct PolicyPublicInput<'a> {
    pub audit: AuditPublicInput<'a>,
    pub policy_hash: &'a [u8; 32],
    pub state_root: &'a [u8; 32],
    pub nullifier_root: &'a [u8; 32],
}

impl PolicyPublicInput<'_> {
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
