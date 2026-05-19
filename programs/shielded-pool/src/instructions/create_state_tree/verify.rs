use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::instruction::CreateStateTreeData;

use crate::{error::ShieldedPoolError, instructions::loader::MutableStateTreeAccounts};

pub fn verify<'a>(
    accounts: &'a [AccountView],
    data: &CreateStateTreeData,
) -> Result<MutableStateTreeAccounts<'a>, ProgramError> {
    if data.height == 0 {
        return Err(ShieldedPoolError::InvalidStateTreeConfig.into());
    }
    crate::instructions::loader::load_mutable_state_tree_accounts(accounts)
}
