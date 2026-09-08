use crate::instructions::shared::caused_by;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    state::{discriminator::RING_CONFIG, RingConfig},
};

/// Values written when initializing a freshly created ring config account.
pub struct RingConfigInitParams {
    pub authority: Address,
    pub program_id: Address,
    /// From `protocol_config.ring_activation_is_permissionless`. A permissioned
    /// pool creates the config inert; `set_ring_activation` admits it.
    pub activated: bool,
    pub bump: u8,
}

impl RingConfigInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(caused_by(ShieldedPoolError::InvalidRingConfig))?;
        if data.len() != RingConfig::SIZE || data.iter().any(|byte| *byte != 0) {
            return Err(ShieldedPoolError::InvalidRingConfig.into());
        }
        let config: &mut RingConfig = bytemuck::from_bytes_mut(&mut data[..]);
        *config = RingConfig {
            discriminator: RING_CONFIG,
            authority: self.authority,
            program_id: self.program_id,
            // Governance-owned; only `set_ring_activation` ever turns it on.
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            activated: u8::from(self.activated),
            bump: self.bump,
        };
        Ok(())
    }
}
