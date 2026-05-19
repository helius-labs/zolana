use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::instruction::AppendStateLeavesData;

use crate::{error::ShieldedPoolError, instructions::loader::MutableStateTreeAccounts};

pub fn verify<'a>(
    accounts: &'a [AccountView],
    data: &AppendStateLeavesData,
) -> Result<MutableStateTreeAccounts<'a>, ProgramError> {
    if data.leaves.is_empty() {
        return Err(ShieldedPoolError::EmptyStateLeafBatch.into());
    }
    crate::instructions::loader::load_mutable_state_tree_accounts(accounts)
}
