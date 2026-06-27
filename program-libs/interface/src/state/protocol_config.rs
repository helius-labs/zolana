use bytemuck::{Pod, Zeroable};
use solana_address::{address_eq, Address};

use super::discriminator::PROTOCOL_CONFIG;
use crate::error::InterfaceError;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ProtocolConfig {
    pub discriminator: u8,
    pub protocol_authority: Address,
    pub tree_creation_authority: Address,
    pub forester_authority: Address,
    pub zone_creation_authority: Address,
    pub tree_creation_is_permissionless: u8,
    pub zone_creation_is_permissionless: u8,
}

impl ProtocolConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn check_discriminator(&self) -> Result<(), InterfaceError> {
        (self.discriminator == PROTOCOL_CONFIG)
            .then_some(())
            .ok_or(InterfaceError::InvalidDiscriminator)
    }

    pub fn check_protocol_authority(&self, authority: &Address) -> Result<(), InterfaceError> {
        address_eq(&self.protocol_authority, authority)
            .then_some(())
            .ok_or(InterfaceError::Unauthorized)
    }

    pub fn check_tree_creation_authority(&self, authority: &Address) -> Result<(), InterfaceError> {
        address_eq(&self.tree_creation_authority, authority)
            .then_some(())
            .ok_or(InterfaceError::Unauthorized)
    }

    pub fn check_forester_authority(&self, authority: &Address) -> Result<(), InterfaceError> {
        address_eq(&self.forester_authority, authority)
            .then_some(())
            .ok_or(InterfaceError::Unauthorized)
    }

    pub fn check_zone_creation_authority(&self, authority: &Address) -> Result<(), InterfaceError> {
        address_eq(&self.zone_creation_authority, authority)
            .then_some(())
            .ok_or(InterfaceError::Unauthorized)
    }

    pub fn allows_permissionless_tree_creation(&self) -> bool {
        self.tree_creation_is_permissionless != 0
    }

    pub fn allows_permissionless_zone_creation(&self) -> bool {
        self.zone_creation_is_permissionless != 0
    }
}

const _: () = assert!(ProtocolConfig::SIZE == 131);
const _: () = assert!(core::mem::align_of::<ProtocolConfig>() == 1);
