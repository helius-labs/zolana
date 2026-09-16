use crate::instructions::shared::caused_by;
use pinocchio::{AccountView, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    state::{cache::CACHE_CAPACITY, discriminator::CACHE, CacheAccount},
};

pub struct CacheInitParams {
    pub bump: u8,
    pub tree_id: u16,
    pub expires_at: i64,
    pub owner_identity: [u8; 32],
    pub rent_sponsor: [u8; 32],
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
            expires_at: self.expires_at.to_le_bytes(),
            owner_identity: self.owner_identity,
            rent_sponsor: self.rent_sponsor,
            commitments: [[0; 32]; CACHE_CAPACITY],
        };
        Ok(())
    }
}
