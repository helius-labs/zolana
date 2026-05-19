use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::CreateStateTreeData;

use super::{init::init_state_tree_account, verify::verify};
use crate::error::ShieldedPoolError;

pub fn process_create_state_tree(
    accounts: &[AccountView],
    data: CreateStateTreeData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    // SAFETY: `MutableStateTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    init_state_tree_account(bytes).map_err(|_| ShieldedPoolError::InvalidStateTreeAccounts)?;
    Ok(())
}
