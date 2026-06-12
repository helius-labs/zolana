use borsh::BorshDeserialize;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::{
    tag, BatchUpdateAddressTreeData, CreateTreeData, CreateProtocolConfigData,
    CreateSplInterfaceData, PauseTreeData, ProoflessShieldIxData, UpdateProtocolConfigData,
    ZoneProoflessShieldIxData,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{
        batch_update_address_tree::processor::process_batch_update_address_tree,
        create_tree::processor::process_create_tree,
        create_spl_interface::processor::process_create_spl_interface,
        proofless_shield::{process_proofless_shield, process_zone_proofless_shield},
        protocol_config::processor::{
            process_create_protocol_config, process_pause_tree, process_update_protocol_config,
        },
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

    // emit_event (spec tag 14): a no-op carrying event bytes; reached only by
    // self-CPI. Indexers authenticate events as inner instructions invoked by
    // this program, so the handler validates nothing and mutates nothing.
    if *ix_tag == tag::EMIT_EVENT {
        return Ok(());
    }

    dispatch!(*ix_tag, payload, program_id, accounts, {
        tag::CREATE_TREE => (CreateTreeData, process_create_tree),
        tag::BATCH_UPDATE_ADDRESS_TREE => (BatchUpdateAddressTreeData, process_batch_update_address_tree),
        tag::PROOFLESS_SHIELD => (ProoflessShieldIxData, process_proofless_shield),
        tag::ZONE_PROOFLESS_SHIELD => (ZoneProoflessShieldIxData, process_zone_proofless_shield),
        tag::CREATE_SPL_INTERFACE => (CreateSplInterfaceData, process_create_spl_interface),
        tag::CREATE_PROTOCOL_CONFIG => (CreateProtocolConfigData, process_create_protocol_config),
        tag::UPDATE_PROTOCOL_CONFIG => (UpdateProtocolConfigData, process_update_protocol_config),
        tag::PAUSE_TREE => (PauseTreeData, process_pause_tree),
    })
}
