use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::CreatePoolTreeData;

use super::{init::init_pool_tree_account, verify::verify};
use crate::instructions::loader;
use crate::error::ShieldedPoolError;

pub fn process_create_pool_tree(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreatePoolTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();
    let bytes = loader::account_data_mut(verified.tree);
    init_pool_tree_account(bytes, program_id, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;
    Ok(())
}
