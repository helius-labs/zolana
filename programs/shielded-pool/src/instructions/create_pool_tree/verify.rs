use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::instruction::CreatePoolTreeData;

use crate::{error::ShieldedPoolError, instructions::loader::MutablePoolTreeAccounts};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    _data: &CreatePoolTreeData,
) -> Result<MutablePoolTreeAccounts<'a>, ProgramError> {
    crate::instructions::loader::load_mutable_pool_tree_accounts(program_id, accounts, true)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts.into())
}
