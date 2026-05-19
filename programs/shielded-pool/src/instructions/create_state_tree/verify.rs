use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::instruction::CreateStateTreeData;

use crate::{
    error::ShieldedPoolError,
    instructions::{create_state_tree::init::HEIGHT, loader::MutableStateTreeAccounts},
};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a [AccountView],
    data: &CreateStateTreeData,
) -> Result<MutableStateTreeAccounts<'a>, ProgramError> {
    // SparseMerkleTree has no canopy concept; we accept any canopy_depth in
    // the request but only the pinned HEIGHT is supported for now.
    if data.height == 0 || (data.height as usize) != HEIGHT {
        return Err(ShieldedPoolError::InvalidStateTreeConfig.into());
    }
    crate::instructions::loader::load_mutable_state_tree_accounts(program_id, accounts, true)
}
