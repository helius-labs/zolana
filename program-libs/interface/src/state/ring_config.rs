use bytemuck::{Pod, Zeroable};
use solana_address::{address_eq, Address};

use super::discriminator::RING_CONFIG;

/// Ring config account (PDA).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Ring program this config belongs to. Set once at `create_ring_config`
    /// (where the `ring_auth` PDA derivation is checked) and thereafter only read
    /// — e.g. as the UTXO's `ring_program_id` — never re-derived.
    pub program_id: Address,
    /// Whether ring-authority transact is enabled, encoded as 0/1 because bool
    /// isn't `Pod`. Governance-owned: only `set_ring_activation` writes it,
    /// because the rail moves UTXOs without owner signatures.
    pub ring_authority_transact_is_enabled: u8,
    /// Whether all operational ring instructions are paused, encoded as 0/1.
    /// Ring-owned.
    pub paused: u8,
    pub activated: u8,
    pub bump: u8,
}

impl RingConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn enabled(&self) -> bool {
        self.ring_authority_transact_is_enabled != 0
    }

    pub fn is_paused(&self) -> bool {
        self.paused != 0
    }

    pub fn is_activated(&self) -> bool {
        self.activated != 0
    }

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == RING_CONFIG
    }

    /// True when `authority` matches the stored ring authority.
    pub fn check_authority(&self, authority: &Address) -> bool {
        address_eq(&self.authority, authority)
    }
}
const _: () = assert!(RingConfig::SIZE == 69);
const _: () = assert!(core::mem::align_of::<RingConfig>() == 1);
