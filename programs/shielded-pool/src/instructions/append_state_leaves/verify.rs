use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::instruction::AppendStateLeavesData;

use crate::{error::ShieldedPoolError, instructions::loader::MutablePoolTreeAccounts};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    data: &AppendStateLeavesData,
) -> Result<MutablePoolTreeAccounts<'a>, ProgramError> {
    if data.leaves.is_empty() {
        return Err(ShieldedPoolError::EmptyStateLeafBatch.into());
    }
    crate::instructions::loader::load_mutable_pool_tree_accounts(program_id, accounts, true)
}
