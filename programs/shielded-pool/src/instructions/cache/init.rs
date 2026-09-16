use crate::instructions::shared::caused_by;
use pinocchio::{AccountView, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    state::{cache::CACHE_CAPACITY, discriminator::CACHE, CacheAccount},
};

pub struct CacheInitParams {
    pub bump: u8,
    pub tree_id: u16,
    pub owner_kind: u8,
    pub owner: [u8; 32],
    pub operation_id: [u8; 32],
    pub rent_sponsor: [u8; 32],
    pub close_authority: [u8; 32],
}

impl CacheInitParams {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(caused_by(ShieldedPoolError::InvalidCache))?;
        if data.len() != CacheAccount::SIZE || data.iter().any(|byte| *byte != 0) {
            return Err(ShieldedPoolError::InvalidCache.into());
        }
        *bytemuck::from_bytes_mut(&mut data) = CacheAccount {
            discriminator: CACHE,
            bump: self.bump,
            frozen: 0,
            tree_id: self.tree_id.to_le_bytes(),
            owner_kind: self.owner_kind,
            owner: self.owner,
            operation_id: self.operation_id,
            rent_sponsor: self.rent_sponsor,
            close_authority: self.close_authority,
            commitments: [[0; 32]; CACHE_CAPACITY],
        };
        Ok(())
    }
}
