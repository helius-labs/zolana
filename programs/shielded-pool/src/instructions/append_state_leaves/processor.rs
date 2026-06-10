use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::AppendStateLeavesData;

use super::verify::verify;
use crate::{
    error::ShieldedPoolError,
    instructions::{create_pool_tree::init::append_state_leaves as append_to_pool, loader},
    log::log,
};

pub fn process_append_state_leaves(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: AppendStateLeavesData,
) -> ProgramResult {
    let verified = verify(program_id, accounts, &data)?;
    let bytes = loader::account_data_mut(verified.tree);
    if append_to_pool(bytes, &data.leaves).is_err() {
        log("append_state_leaves: state sub-tree append failed");
        return Err(ShieldedPoolError::StateAppendFailed.into());
    }
    Ok(())
}
