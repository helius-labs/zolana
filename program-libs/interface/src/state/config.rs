use bytemuck::{Pod, Zeroable};

use super::discriminator::{PROTOCOL_CONFIG, ZONE_CONFIG};

pub const PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES: usize = 16;

/// Protocol config account (PDA). 8-byte discriminator region (byte 0 holds the
/// discriminator; bytes 1..8 reserved) matching the tree-account convention.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ProtocolConfig {
    pub discriminator: u8,
    pub _disc_reserved: [u8; 7],
    pub authority: [u8; 32],
    pub merge_authority_count: u64,
    pub merge_authorities: [[u8; 32]; PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES],
}

impl ProtocolConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Authorities actually set (the first `merge_authority_count`).
    pub fn active_merge_authorities(&self) -> &[[u8; 32]] {
        let n = (self.merge_authority_count as usize).min(PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES);
        &self.merge_authorities[..n]
    }

    pub fn has_discriminator(&self) -> bool {
        self.discriminator == PROTOCOL_CONFIG
    }
}

/// Zone config account (PDA). Same 8-byte discriminator region.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ZoneConfig {
    pub discriminator: u8,
    pub _disc_reserved: [u8; 7],
    pub authority: [u8; 32],
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
}

// Lock the on-chain layout: these account sizes are observable by clients and
// tests, so the byte layout must not drift when the structs change.
const _: () = assert!(ProtocolConfig::SIZE == 560);
const _: () = assert!(core::mem::align_of::<ProtocolConfig>() == 8);
const _: () = assert!(ZoneConfig::SIZE == 42);
const _: () = assert!(core::mem::align_of::<ZoneConfig>() == 1);
