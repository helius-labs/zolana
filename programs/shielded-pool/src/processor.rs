use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::{
    tag, BatchUpdateAddressTreeData, CreatePocketConfigData, CreatePoolTreeData,
    CreateProtocolConfigData, CreateSplInterfaceData, PauseTreeData, ProoflessShieldData,
    TransactData, UpdatePocketConfigData, UpdatePocketConfigOwnerData, UpdateProtocolConfigData,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{
        batch_update_address_tree::processor::process_batch_update_address_tree,
        create_pool_tree::processor::process_create_pool_tree,
        create_spl_interface::processor::process_create_spl_interface,
        pocket_config::processor::{
            process_create_pocket_config, process_update_pocket_config,
            process_update_pocket_config_owner,
        },
        protocol_config::processor::{
            process_create_protocol_config, process_pause_tree, process_update_protocol_config,
        },
        transact::{processor::process_transact, proofless::process_proofless_shield},
    },
};

/// Table-driven instruction dispatch.
///
/// Every arm shares the same shape — borsh-decode the payload into the
/// instruction's data type (mapping a decode failure to InvalidInstructionData)
/// and call its handler — so express it once here instead of repeating it per
/// instruction. Unknown/reserved tags fall through to InvalidInstructionData.
macro_rules! dispatch {
    (
        $tag:expr, $payload:expr, $program_id:expr, $accounts:expr,
        { $($const:path => ($data:ty, $handler:path)),+ $(,)? }
    ) => {
        match $tag {
            $(
                $const => {
                    let data = <$data>::try_from_slice($payload)
                        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
                    $handler($program_id, $accounts, data)
                }
            )+
            _ => Err(ProgramError::InvalidInstructionData),
        }
    };
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_tag, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    dispatch!(*ix_tag, payload, program_id, accounts, {
        tag::CREATE_POOL_TREE => (CreatePoolTreeData, process_create_pool_tree),
        tag::BATCH_UPDATE_ADDRESS_TREE => (BatchUpdateAddressTreeData, process_batch_update_address_tree),
        tag::TRANSACT => (TransactData, process_transact),
        tag::PROOFLESS_SHIELD => (ProoflessShieldData, process_proofless_shield),
        tag::CREATE_SPL_INTERFACE => (CreateSplInterfaceData, process_create_spl_interface),
        tag::CREATE_PROTOCOL_CONFIG => (CreateProtocolConfigData, process_create_protocol_config),
        tag::UPDATE_PROTOCOL_CONFIG => (UpdateProtocolConfigData, process_update_protocol_config),
        tag::PAUSE_TREE => (PauseTreeData, process_pause_tree),
        tag::CREATE_POCKET_CONFIG => (CreatePocketConfigData, process_create_pocket_config),
        tag::UPDATE_POCKET_CONFIG_OWNER => (UpdatePocketConfigOwnerData, process_update_pocket_config_owner),
        tag::UPDATE_POCKET_CONFIG => (UpdatePocketConfigData, process_update_pocket_config),
    })
}
