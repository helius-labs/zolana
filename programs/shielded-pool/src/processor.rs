use borsh::BorshDeserialize;
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::ShieldedPoolInstruction;

use crate::{
    error::ShieldedPoolError,
    instructions::{
        batch_update_address_tree::process_batch_update_address_tree,
        create_address_tree::process_create_address_tree,
        insert_addresses::process_insert_addresses,
    },
};

pub fn process_instruction(
    _program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = ShieldedPoolInstruction::try_from_slice(instruction_data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;

    match instruction {
        ShieldedPoolInstruction::CreateAddressTree(data) => {
            process_create_address_tree(accounts, data)
        }
        ShieldedPoolInstruction::InsertAddresses(data) => process_insert_addresses(accounts, data),
        ShieldedPoolInstruction::BatchUpdateAddressTree(data) => {
            process_batch_update_address_tree(accounts, data)
        }
    }
}
