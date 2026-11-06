use pinocchio::{error::ProgramError, AccountView, Address};
use spr_interface::{SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};

use crate::error::DynamicSwapError;

/// The owner field of an SPL Token or Token-2022 account (same offset in both).
const TOKEN_ACCOUNT_OWNER_RANGE: core::ops::Range<usize> = 32..64;

/// The wallet that owns an SPL Token or Token-2022 account.
#[inline(always)]
pub fn load_token_account_owner(account: &AccountView) -> Result<Address, ProgramError> {
    if !account.owned_by(&Address::new_from_array(SPL_TOKEN_PROGRAM_ID))
        && !account.owned_by(&Address::new_from_array(SPL_TOKEN_2022_PROGRAM_ID))
    {
        return Err(DynamicSwapError::InterfaceTransferMismatch.into());
    }
    let data = account
        .try_borrow()
        .map_err(|_| DynamicSwapError::InterfaceTransferMismatch)?;
    let owner: [u8; 32] = data
        .get(TOKEN_ACCOUNT_OWNER_RANGE)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(DynamicSwapError::InterfaceTransferMismatch)?;
    Ok(Address::new_from_array(owner))
}
