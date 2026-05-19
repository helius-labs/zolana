use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::AppendStateLeavesData;

use super::verify::verify;
use crate::{error::ShieldedPoolError, instructions::create_state_tree::init::append_leaves_to_account};

pub fn process_append_state_leaves(
    accounts: &[AccountView],
    data: AppendStateLeavesData,
) -> ProgramResult {
    let verified = verify(accounts, &data)?;
    // SAFETY: `MutableStateTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    append_leaves_to_account(bytes, &data.leaves)
        .map_err(|_| ShieldedPoolError::InvalidStateTreeAccounts)?;
    Ok(())
}
