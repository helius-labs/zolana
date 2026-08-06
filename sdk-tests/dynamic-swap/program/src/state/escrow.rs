use bytemuck::{from_bytes_mut, Pod, Zeroable};
use pinocchio::{account::RefMut, error::ProgramError, AccountView, Address};

use super::discriminator::ESCROW;
use crate::error::DynamicSwapError;

/// Public lifecycle state. Private terms and the payout recipient remain
/// committed in the order UTXO and its encrypted note.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Escrow {
    pub discriminator: u8,
    pub bump: u8,
    pub _pad: [u8; 6],
    pub pair: Address,
    pub escrow_utxo_hash: [u8; 32],
    pub order_commitment: [u8; 32],
    pub execution_price: u64,
    pub quote_version: u64,
    pub reserved_liability: u64,
    pub created_at_unix_ts: i64,
    pub expires_at_unix_ts: i64,
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

const _: () = assert!(Escrow::SIZE == 144);

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
