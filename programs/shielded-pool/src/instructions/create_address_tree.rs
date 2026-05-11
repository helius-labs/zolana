use pinocchio::{AccountView, ProgramResult};
use zolana_interface::instruction::CreateAddressTreeData;

use crate::error::ShieldedPoolError;

pub fn process_create_address_tree(
    _accounts: &[AccountView],
    data: CreateAddressTreeData,
) -> ProgramResult {
    if data.height == 0 || data.queue_capacity == 0 {
        return Err(ShieldedPoolError::InvalidAddressTreeConfig.into());
    }
    let _batched_tree_params =
        light_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData {
            height: data.height as u32,
            input_queue_batch_size: data.queue_capacity as u64,
            ..Default::default()
        };
    Ok(())
}
