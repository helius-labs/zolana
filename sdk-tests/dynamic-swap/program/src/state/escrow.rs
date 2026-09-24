use bytemuck::{from_bytes, from_bytes_mut, Pod, Zeroable};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address,
};

use super::discriminator::ESCROW;
use crate::error::DynamicSwapError;

/// A user escrow order: `owner` is the taker's Solana pubkey -- it funded the
/// escrow account (rent returns to it on settle/cancel) and it signed the
/// creation. The payout destination is NOT stored here: it is the taker's own
/// owner-hash, bound in-circuit to the source UTXO's owner and committed as the
/// order UTXO's `DataHash`, so it stays confidential. `create_escrow` prices the
/// order at creation, writing a nonzero `execution_price` (the pair's current
/// price); `settle` fills it before `created_at + Pair.expiry_slots`, `cancel`
/// refunds it after. Each order resolves independently -- there is no shared
/// pool and no ordering between orders.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Escrow {
    pub discriminator: u8,
    pub bump: u8,
    pub _pad: [u8; 6],
    pub pair: Address,
    /// The order UTXO's hash, read from the transact CPI's own outputs at
    /// creation. Also the escrow account's PDA seed, so a taker can hold
    /// concurrent orders.
    pub order_utxo_hash: [u8; 32],
    pub owner: Address,
    /// The slot `create_escrow` executed in, read from the Clock sysvar.
    pub created_at: u64,
    pub execution_price: u64,
}

impl Escrow {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED_PREFIX: &'static [u8] = b"escrow";

    pub fn check_discriminator(&self) -> Result<(), ProgramError> {
        (self.discriminator == ESCROW)
            .then_some(())
            .ok_or_else(|| DynamicSwapError::InvalidInstructionData.into())
    }
}

const _: () = assert!(Escrow::SIZE == 120);

#[inline(always)]
pub fn load_escrow(account: &AccountView) -> Result<Ref<'_, Escrow>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if data.len() != Escrow::SIZE {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let escrow = Ref::map(data, |d| from_bytes::<Escrow>(d));
    escrow.check_discriminator()?;
    Ok(escrow)
}

#[inline(always)]
pub fn load_escrow_mut(account: &mut AccountView) -> Result<RefMut<'_, Escrow>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if data.len() != Escrow::SIZE {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let escrow = RefMut::map(data, |d| from_bytes_mut::<Escrow>(d));
    escrow.check_discriminator()?;
    Ok(escrow)
}
