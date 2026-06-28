use bytemuck::{Pod, Zeroable};
use solana_address::{address_eq, Address};

use super::discriminator::ZONE_CONFIG;

/// Zone config account (PDA).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ZoneConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Zone program this config belongs to. Set once at `create_zone_config`
    /// (where the `zone_auth` PDA derivation is checked) and thereafter only read
    /// — e.g. as the UTXO's `zone_program_id` — never re-derived.
    pub program_id: Address,
    /// 0/1 -- bool isn't `Pod`.
    pub zone_authority_transact_is_enabled: u8,
    pub bump: u8,
}

impl ZoneConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn enabled(&self) -> bool {
        self.zone_authority_transact_is_enabled != 0
    }

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == ZONE_CONFIG
    }

    /// True when `authority` matches the stored zone authority.
    pub fn check_authority(&self, authority: &Address) -> bool {
        address_eq(&self.authority, authority)
    }
}
const _: () = assert!(ZoneConfig::SIZE == 67);
const _: () = assert!(core::mem::align_of::<ZoneConfig>() == 1);
