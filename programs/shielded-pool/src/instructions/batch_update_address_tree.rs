use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::BatchUpdateAddressTreeData;

use crate::error::ShieldedPoolError;

pub fn process_batch_update_address_tree(
    _accounts: &[AccountView],
    data: BatchUpdateAddressTreeData,
) -> ProgramResult {
    if data.new_root == [0u8; 32] {
        return Err(ShieldedPoolError::EmptyBatchUpdateRoot.into());
    }
    Ok(())
}
