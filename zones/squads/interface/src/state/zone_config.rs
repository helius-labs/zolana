//! Zone configuration account: the per-program singleton holding the auditor
//! keys, optional co-signer, proposal lifetime bound, and merge authorities.

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use super::discriminator;
use crate::{
    types::{Address, P256Pubkey},
    ZONE_CONFIG_PDA_SEED,
};

/// Singleton zone config, derived at `[b"zone_config"]`. Variable-length because
/// `auditor_keys` and `merge_authorities` are vectors, so it (de)serializes with
/// wincode rather than a zero-copy `bytemuck` cast.
#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct ZoneConfig {
    pub discriminator: u8,
    pub authority: Address,
    pub co_signer: Address,
    pub max_proposal_lifetime: i64,
    #[wincode(with = "containers::Vec<[u8; 33], FixIntLen<u8>>")]
    pub auditor_keys: Vec<P256Pubkey>,
    #[wincode(with = "containers::Vec<Address, FixIntLen<u8>>")]
    pub merge_authorities: Vec<Address>,
}

impl ZoneConfig {
    pub const DISCRIMINATOR: u8 = discriminator::ZONE_CONFIG;
    pub const SEED: &'static [u8] = ZONE_CONFIG_PDA_SEED;

    /// Build a config with the discriminator already stamped.
    pub fn new(
        authority: Address,
        co_signer: Address,
        max_proposal_lifetime: i64,
        auditor_keys: Vec<P256Pubkey>,
        merge_authorities: Vec<Address>,
    ) -> Self {
        Self {
            discriminator: Self::DISCRIMINATOR,
            authority,
            co_signer,
            max_proposal_lifetime,
            auditor_keys,
            merge_authorities,
        }
    }

    /// Allocation size for `auditors` auditor keys and `merge_authorities`
    /// merge authorities, accounting for the two 1-byte wincode length prefixes.
    pub fn account_size(auditors: usize, merge_authorities: usize) -> usize {
        75 + 33 * auditors + 32 * merge_authorities
    }

    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
