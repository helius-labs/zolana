use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    state::{discriminator::ZONE_CONFIG, ZoneConfig},
};

/// Values written when initializing a freshly created zone config account.
pub struct ZoneConfigInitParams {
    pub authority: Address,
    pub program_id: Address,
    pub zone_authority_transact_is_enabled: bool,
    pub bump: u8,
}

impl ZoneConfigInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| ShieldedPoolError::InvalidZoneConfig)?;
        if data.len() != ZoneConfig::SIZE || data.iter().any(|byte| *byte != 0) {
            return Err(ShieldedPoolError::InvalidZoneConfig.into());
        }
        let config: &mut ZoneConfig = bytemuck::from_bytes_mut(&mut data[..]);
        *config = ZoneConfig {
            discriminator: ZONE_CONFIG,
            authority: self.authority,
            program_id: self.program_id,
            zone_authority_transact_is_enabled: u8::from(self.zone_authority_transact_is_enabled),
            bump: self.bump,
        };
        Ok(())
    }
}
