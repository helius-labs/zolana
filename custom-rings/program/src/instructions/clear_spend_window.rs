use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_authorized_config, load_spend_window},
        shared::close_into,
    },
};

#[inline(never)]
pub fn process_clear_spend_window_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mint: [u8; 32] = data
        .try_into()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let mint = Address::new_from_array(mint);

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let window_account = iter.next_mut("window")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    // 1. Authenticate the authority and the mint whose public cap is removed.
    load_authorized_config(program_id, config_account, authority)?;
    if load_spend_window(program_id, window_account, &mint)?.is_none() {
        return Err(CustomRingError::InvalidSpendWindow.into());
    }
    // 2. Remove public settlement accounting without changing private outflow caps.
    close_into(
        window_account,
        rent_recipient,
        CustomRingError::InvalidSpendWindow,
    )
}
