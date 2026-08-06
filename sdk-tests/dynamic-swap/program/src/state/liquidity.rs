use bytemuck::{from_bytes_mut, Pod, Zeroable};
use pinocchio::{account::RefMut, error::ProgramError, AccountView, Address};

use super::discriminator::LIQUIDITY;
use crate::error::DynamicSwapError;

/// Per-pair liquidity commitment: `available_hash` is the live pool UTXO's
/// own `utxo_hash`. No public balance is stored -- every instruction that
/// spends/recreates the pool UTXO overwrites this with the new hash read
/// straight from the CPI's `transact.outputs[..]`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Liquidity {
    pub discriminator: u8,
    pub bump: u8,
    pub _pad: [u8; 6],
    pub pair: Address,
    pub available_hash: [u8; 32],
    pub available_slots: u64,
    pub reserved_liability: u64,
}

impl Liquidity {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SEED_PREFIX: &'static [u8] = b"liquidity";

    pub fn check_discriminator(&self) -> Result<(), ProgramError> {
        (self.discriminator == LIQUIDITY)
            .then_some(())
            .ok_or_else(|| DynamicSwapError::InvalidInstructionData.into())
    }
}

const _: () = assert!(Liquidity::SIZE == 88);

#[inline(always)]
pub fn load_liquidity_mut(
    account: &mut AccountView,
) -> Result<RefMut<'_, Liquidity>, ProgramError> {
    if !account.is_writable() || !account.owned_by(&crate::ID) {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if data.len() != Liquidity::SIZE {
        return Err(DynamicSwapError::InvalidInstructionData.into());
    }
    let liquidity = RefMut::map(data, |d| from_bytes_mut::<Liquidity>(d));
    liquidity.check_discriminator()?;
    Ok(liquidity)
}
