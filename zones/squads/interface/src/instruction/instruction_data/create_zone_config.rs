//! `create_zone_config` (tag 3) instruction data (spec: squads
//! `create_zone_config`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::types::{Address, P256Pubkey};

/// `create_zone_config` instruction data (spec: squads `create_zone_config`).
/// Sets the zone's authority, co-signer, proposal-lifetime bound, auditor keys
/// (exactly one for now), and merge authorities.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateZoneConfigIxData {
    /// Authority that can update the zone; the default freezes it.
    pub authority: Address,
    /// Co-signer required on every spend; the default disables co-signing.
    pub co_signer: Address,
    /// Upper bound on a proposal's `expiry`, in seconds from creation.
    pub max_proposal_lifetime: i64,
    /// Zone auditor keys; must contain exactly one for now.
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub auditor_keys: Vec<P256Pubkey>,
    /// Authorities allowed to run merge_transact.
    #[wincode(with = "containers::Vec<Address, FixIntLen<u8>>")]
    pub merge_authorities: Vec<Address>,
}

impl CreateZoneConfigIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
