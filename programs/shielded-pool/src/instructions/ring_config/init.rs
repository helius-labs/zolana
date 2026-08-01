use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    state::{discriminator::RING_CONFIG, RingConfig},
};

/// Values written when initializing a freshly created ring config account.
pub struct RingConfigInitParams {
    pub authority: Address,
    pub program_id: Address,
    pub ring_authority_transact_is_enabled: bool,
    pub bump: u8,
}

impl RingConfigInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| ShieldedPoolError::InvalidRingConfig)?;
        if data.len() != RingConfig::SIZE || data.iter().any(|byte| *byte != 0) {
            return Err(ShieldedPoolError::InvalidRingConfig.into());
        }
        let config: &mut RingConfig = bytemuck::from_bytes_mut(&mut data[..]);
        *config = RingConfig {
            discriminator: RING_CONFIG,
            authority: self.authority,
            program_id: self.program_id,
            ring_authority_transact_is_enabled: u8::from(self.ring_authority_transact_is_enabled),
            bump: self.bump,
        };
        Ok(())
    }
}
