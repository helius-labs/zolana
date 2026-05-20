use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::CreatePoolTreeData;

use super::{init::init_pool_tree_account, verify::verify};
use crate::{error::ShieldedPoolError, events::emit_pool_tree_created};

pub fn process_create_pool_tree(
    program_id: &Address,
    accounts: &[AccountView],
    data: CreatePoolTreeData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();
    // SAFETY: `MutablePoolTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    init_pool_tree_account(bytes, program_id, &tree_pubkey)
        .map_err(|_| ShieldedPoolError::InvalidPoolTreeAccounts)?;

    emit_pool_tree_created(&tree_pubkey, program_id);
    Ok(())
}
