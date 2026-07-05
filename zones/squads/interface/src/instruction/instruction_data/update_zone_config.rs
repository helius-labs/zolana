//! `update_zone_config` (tag 4) instruction data (spec: squads
//! `update_zone_config`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::types::{Address, P256Pubkey};

/// `update_zone_config` instruction data (spec: squads `update_zone_config`).
/// Overwrites the zone config's mutable fields. Same field shape as
/// `create_zone_config`. Setting `authority` to the default freezes the config.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateZoneConfigIxData {
    /// New update authority; the default freezes the config.
    pub authority: Address,
    /// New co-signer; the default disables co-signing.
    pub co_signer: Address,
    /// New upper bound on a proposal's `expiry`, in seconds from creation.
    pub max_proposal_lifetime: i64,
    /// New zone auditor keys; must contain exactly one for now.
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub auditor_keys: Vec<P256Pubkey>,
    /// New authorities allowed to run merge_transact.
    #[wincode(with = "containers::Vec<Address, FixIntLen<u8>>")]
    pub merge_authorities: Vec<Address>,
}

impl UpdateZoneConfigIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
