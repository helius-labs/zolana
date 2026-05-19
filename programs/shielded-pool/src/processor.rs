use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::{
    tag, AppendStateLeavesData, BatchUpdateAddressTreeData, CreateAddressTreeData,
    CreateStateTreeData, InsertAddressesData,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{
        append_state_leaves::processor::process_append_state_leaves,
        batch_update_address_tree::processor::process_batch_update_address_tree,
        create_address_tree::processor::process_create_address_tree,
        create_state_tree::processor::process_create_state_tree,
        insert_addresses::processor::process_insert_addresses,
    },
};

pub fn process_instruction(
    _program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_tag, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_tag {
        tag::CREATE_ADDRESS_TREE => {
            let data = CreateAddressTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_address_tree(accounts, data)
        }
        tag::INSERT_ADDRESSES => {
            let data = InsertAddressesData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_insert_addresses(accounts, data)
        }
        tag::BATCH_UPDATE_ADDRESS_TREE => {
            let data = BatchUpdateAddressTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_batch_update_address_tree(accounts, data)
        }
        tag::CREATE_STATE_TREE => {
            let data = CreateStateTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_state_tree(accounts, data)
        }
        tag::APPEND_STATE_LEAVES => {
            let data = AppendStateLeavesData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_append_state_leaves(accounts, data)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
