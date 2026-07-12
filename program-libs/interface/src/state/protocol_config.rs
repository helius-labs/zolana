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
    pub spl_interface_creation_is_permissionless: u8,
}

impl ProtocolConfig {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn check_discriminator(&self) -> Result<(), InterfaceError> {
        (self.discriminator == PROTOCOL_CONFIG)
            .then_some(())
            .ok_or(InterfaceError::InvalidDiscriminator)
    }

    /// Zero-copy view over an exact protocol-config account payload.
    pub fn from_account_bytes(data: &[u8]) -> Result<&Self, InterfaceError> {
        if data.len() != Self::SIZE {
            return Err(InterfaceError::InvalidAccountData);
        }
        let config: &Self =
            bytemuck::try_from_bytes(data).map_err(|_| InterfaceError::InvalidAccountData)?;
        config.check_discriminator()?;
        Ok(config)
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

    pub fn allows_permissionless_spl_interface_creation(&self) -> bool {
        self.spl_interface_creation_is_permissionless != 0
    }
}

const _: () = assert!(ProtocolConfig::SIZE == 132);
const _: () = assert!(core::mem::align_of::<ProtocolConfig>() == 1);

#[cfg(test)]
mod tests {
    use super::*;

    fn protocol_config() -> ProtocolConfig {
        ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: Address::new_from_array([1; 32]),
            tree_creation_authority: Address::new_from_array([2; 32]),
            forester_authority: Address::new_from_array([3; 32]),
            zone_creation_authority: Address::new_from_array([4; 32]),
            tree_creation_is_permissionless: 0,
            zone_creation_is_permissionless: 0,
            spl_interface_creation_is_permissionless: 1,
        }
    }

    #[test]
    fn parses_only_exact_protocol_config_bytes() {
        let config = protocol_config();
        assert_eq!(
            ProtocolConfig::from_account_bytes(bytemuck::bytes_of(&config)).unwrap(),
            &config
        );

        assert_eq!(
            ProtocolConfig::from_account_bytes(&[0; ProtocolConfig::SIZE - 1]),
            Err(InterfaceError::InvalidAccountData)
        );
        let mut too_long = bytemuck::bytes_of(&config).to_vec();
        too_long.push(0);
        assert_eq!(
            ProtocolConfig::from_account_bytes(&too_long),
            Err(InterfaceError::InvalidAccountData)
        );

        let mut wrong_discriminator = config;
        wrong_discriminator.discriminator = 0;
        assert_eq!(
            ProtocolConfig::from_account_bytes(bytemuck::bytes_of(&wrong_discriminator)),
            Err(InterfaceError::InvalidDiscriminator)
        );
    }
}
