use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::AppendStateLeavesData;

use super::verify::verify;
use crate::{
    error::ShieldedPoolError,
    events::emit_state_leaves_appended,
    instructions::create_pool_tree::init::{
        append_state_leaves as append_to_pool, read_state_next_index,
    },
};

pub fn process_append_state_leaves(
    program_id: &Address,
    accounts: &[AccountView],
    data: AppendStateLeavesData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let tree_pubkey = *verified.tree.address();
    // SAFETY: `MutablePoolTreeAccounts::tree` is the writable account passed
    // by the caller and not aliased with any other borrowed account.
    let bytes = unsafe { verified.tree.borrow_unchecked_mut() };
    let start_index = read_state_next_index(bytes) as u64;
    let new_root = append_to_pool(bytes, &data.leaves)
        .map_err(|_| ShieldedPoolError::PoolTreeMutationFailed)?;
    emit_state_leaves_appended(&tree_pubkey, start_index, new_root, &data.leaves);
    Ok(())
}
