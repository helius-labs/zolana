use custom_ring_interface::{CustomRingError, SetInsertFeeIxData};
use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::instructions::loader::load_authorized_config_mut;

#[inline(never)]
pub fn process_set_insert_fee_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = SetInsertFeeIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    // 1. The config authority sets the fee its own writes never pay.
    let mut config = load_authorized_config_mut(program_id, config, authority)?;
    // 2. A fee under the rent minimum cannot fund an empty authority, every paid write would fail.
    let fee = ix.fee();
    if fee != 0 && fee < Rent::get()?.try_minimum_balance(0)? {
        return Err(CustomRingError::InsertFeeBelowRent.into());
    }
    config.insert_fee = ix.fee;
    Ok(())
}
