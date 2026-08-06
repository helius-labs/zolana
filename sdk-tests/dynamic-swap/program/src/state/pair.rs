use bytemuck::{from_bytes, from_bytes_mut, Pod, Zeroable};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address,
};

use super::discriminator::PAIR;
use crate::error::DynamicSwapError;

/// Public quote configuration. The exact destination-asset balance is stored
/// only in the liquidity UTXO; this account exposes conservative capacity.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Pair {
    pub discriminator: u8,
    pub bump: u8,
    pub _pad: [u8; 6],
    pub authority: Address,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    pub price: u64,
    pub max_order_size: u64,
    pub quote_version: u64,
    /// Refresh when advertised capacity, expressed in destination base units,
    /// falls below this threshold.
    pub capacity_refresh_threshold: u64,
    pub authority_owner_hash: [u8; 32],
    pub source_asset: [u8; 32],
    pub destination_asset: [u8; 32],
    /// Compressed default-zone viewing pubkey used for order-note encryption.
    pub settlement_viewing_pubkey_x: [u8; 32],
    pub settlement_viewing_pubkey_prefix: u8,
    pub _tail_pad: [u8; 7],
}

impl Pair {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED_PREFIX: &'static [u8] = b"pair";

    pub fn check_discriminator(&self) -> Result<(), ProgramError> {
        (self.discriminator == PAIR)
            .then_some(())
            .ok_or_else(|| DynamicSwapError::InvalidInstructionData.into())
    }
}

const _: () = assert!(Pair::SIZE == 224);

#[inline(always)]
pub fn load_pair(account: &AccountView) -> Result<Ref<'_, Pair>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if data.len() != Pair::SIZE {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let pair = Ref::map(data, |d| from_bytes::<Pair>(d));
    pair.check_discriminator()?;
    Ok(pair)
}

#[inline(always)]
pub fn load_pair_mut(account: &mut AccountView) -> Result<RefMut<'_, Pair>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if data.len() != Pair::SIZE {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let pair = RefMut::map(data, |d| from_bytes_mut::<Pair>(d));
    pair.check_discriminator()?;
    Ok(pair)
}
