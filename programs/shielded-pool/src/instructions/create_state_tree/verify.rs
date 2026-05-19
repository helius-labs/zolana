use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::instruction::CreateStateTreeData;

use crate::{
    error::ShieldedPoolError,
    instructions::{create_state_tree::init::HEIGHT, loader::MutableStateTreeAccounts},
};

pub fn verify<'a>(
    accounts: &'a [AccountView],
    data: &CreateStateTreeData,
) -> Result<MutableStateTreeAccounts<'a>, ProgramError> {
    if data.height == 0
        || (data.height as usize) != HEIGHT
        || (data.canopy_depth as usize) > HEIGHT
    {
        return Err(ShieldedPoolError::InvalidStateTreeConfig.into());
    }
    crate::instructions::loader::load_mutable_state_tree_accounts(accounts)
}
