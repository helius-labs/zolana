use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::instruction::InsertAddressesData;

use crate::{error::ShieldedPoolError, instructions::loader::MutablePoolTreeAccounts};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a [AccountView],
    data: &InsertAddressesData,
) -> Result<MutablePoolTreeAccounts<'a>, ProgramError> {
    if data.addresses.is_empty() {
        return Err(ShieldedPoolError::EmptyAddressBatch.into());
    }
    crate::instructions::loader::load_mutable_pool_tree_accounts(program_id, accounts, true)
}
