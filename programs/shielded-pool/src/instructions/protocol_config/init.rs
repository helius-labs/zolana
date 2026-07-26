use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    state::{discriminator::PROTOCOL_CONFIG, ProtocolConfig},
};

/// Values written when initializing a freshly created protocol config account.
pub struct ProtocolConfigInitParams {
    pub protocol_authority: Address,
    pub tree_creation_authority: Address,
    pub tree_creation_is_permissionless: u8,
    pub forester_authority: Address,
    pub zone_creation_authority: Address,
    pub zone_creation_is_permissionless: u8,
    pub spl_interface_creation_is_permissionless: u8,
}

impl ProtocolConfigInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| ShieldedPoolError::InvalidProtocolConfig)?;
        if data.len() != ProtocolConfig::SIZE || data.iter().any(|byte| *byte != 0) {
            return Err(ShieldedPoolError::InvalidProtocolConfig.into());
        }
        let config: &mut ProtocolConfig = bytemuck::from_bytes_mut(&mut data[..]);
        *config = ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: self.protocol_authority,
            tree_creation_authority: self.tree_creation_authority,
            forester_authority: self.forester_authority,
            zone_creation_authority: self.zone_creation_authority,
            tree_creation_is_permissionless: self.tree_creation_is_permissionless,
            zone_creation_is_permissionless: self.zone_creation_is_permissionless,
            spl_interface_creation_is_permissionless: self.spl_interface_creation_is_permissionless,
        };
        Ok(())
    }
}
