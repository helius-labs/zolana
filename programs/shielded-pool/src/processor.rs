use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::{
    tag, AppendStateLeavesData, BatchUpdateAddressTreeData, BatchUpdateNullifierTreeData,
    CreatePocketConfigData, CreatePoolTreeData, CreateProtocolConfigData, CreateSplInterfaceData,
    InsertAddressesData, PauseTreeData, ProoflessShieldData, TransactData, UpdatePocketConfigData,
    UpdatePocketConfigOwnerData, UpdateProtocolConfigData,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{
        append_state_leaves::processor::process_append_state_leaves,
        batch_update_address_tree::processor::process_batch_update_address_tree,
        batch_update_nullifier_tree::processor::process_batch_update_nullifier_tree,
        create_pool_tree::processor::process_create_pool_tree,
        create_spl_interface::processor::process_create_spl_interface,
        insert_addresses::processor::process_insert_addresses,
        pocket_config::processor::{
            process_create_pocket_config, process_update_pocket_config,
            process_update_pocket_config_owner,
        },
        protocol_config::processor::{
            process_create_protocol_config, process_pause_tree, process_update_protocol_config,
        },
        transact::processor::process_transact,
        transact::proofless::process_proofless_shield,
    },
};

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_tag, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_tag {
        tag::CREATE_POOL_TREE => {
            let data = CreatePoolTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_pool_tree(program_id, accounts, data)
        }
        tag::INSERT_ADDRESSES => {
            let data = InsertAddressesData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_insert_addresses(program_id, accounts, data)
        }
        tag::BATCH_UPDATE_ADDRESS_TREE => {
            let data = BatchUpdateAddressTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_batch_update_address_tree(program_id, accounts, data)
        }
        tag::BATCH_UPDATE_NULLIFIER_TREE => {
            let data = BatchUpdateNullifierTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_batch_update_nullifier_tree(program_id, accounts, data)
        }
        tag::APPEND_STATE_LEAVES => {
            let data = AppendStateLeavesData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_append_state_leaves(program_id, accounts, data)
        }
        tag::TRANSACT => {
            let data = TransactData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_transact(program_id, accounts, data)
        }
        tag::PROOFLESS_SHIELD => {
            let data = ProoflessShieldData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_proofless_shield(program_id, accounts, data)
        }
        tag::CREATE_SPL_INTERFACE => {
            let data = CreateSplInterfaceData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_spl_interface(program_id, accounts, data)
        }
        tag::CREATE_PROTOCOL_CONFIG => {
            let data = CreateProtocolConfigData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_protocol_config(program_id, accounts, data)
        }
        tag::UPDATE_PROTOCOL_CONFIG => {
            let data = UpdateProtocolConfigData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_update_protocol_config(program_id, accounts, data)
        }
        tag::PAUSE_TREE => {
            let data = PauseTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_pause_tree(program_id, accounts, data)
        }
        tag::CREATE_POCKET_CONFIG => {
            let data = CreatePocketConfigData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_pocket_config(program_id, accounts, data)
        }
        tag::UPDATE_POCKET_CONFIG_OWNER => {
            let data = UpdatePocketConfigOwnerData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_update_pocket_config_owner(program_id, accounts, data)
        }
        tag::UPDATE_POCKET_CONFIG => {
            let data = UpdatePocketConfigData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_update_pocket_config(program_id, accounts, data)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
