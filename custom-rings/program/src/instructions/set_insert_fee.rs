use custom_ring_interface::SetInsertFeeIxData;
use pinocchio::{AccountView, Address, ProgramResult};
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
    load_authorized_config_mut(program_id, config, authority)?.insert_fee = ix.fee;
    Ok(())
}
