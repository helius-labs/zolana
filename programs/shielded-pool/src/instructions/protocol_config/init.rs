use crate::instructions::shared::caused_by;
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
    pub ring_creation_authority: Address,
    pub ring_activation_is_permissionless: u8,
    pub spl_interface_creation_is_permissionless: u8,
    pub fee_authority: Address,
}

impl ProtocolConfigInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(caused_by(ShieldedPoolError::InvalidProtocolConfig))?;
        if data.len() != ProtocolConfig::SIZE || data.iter().any(|byte| *byte != 0) {
            return Err(ShieldedPoolError::InvalidProtocolConfig.into());
        }
        let config: &mut ProtocolConfig = bytemuck::from_bytes_mut(&mut data[..]);
        *config = ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            protocol_authority: self.protocol_authority,
            tree_creation_authority: self.tree_creation_authority,
            forester_authority: self.forester_authority,
            ring_creation_authority: self.ring_creation_authority,
            fee_authority: self.fee_authority,
            tree_creation_is_permissionless: self.tree_creation_is_permissionless,
            ring_activation_is_permissionless: self.ring_activation_is_permissionless,
            spl_interface_creation_is_permissionless: self.spl_interface_creation_is_permissionless,
            next_tree_id: 0,
        };
        Ok(())
    }
}
