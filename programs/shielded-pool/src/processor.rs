use borsh::BorshDeserialize;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::{
    tag, BatchUpdateNullifierTreeData, CreateProtocolConfigData, CreateTreeData,
    CreateZoneConfigData, PauseTreeData, ProoflessShieldIxData, UpdateProtocolConfigData,
    UpdateZoneConfigData, UpdateZoneConfigOwnerData, ZoneProoflessShieldIxData,
};

use crate::{
    error::ShieldedPoolError,
    instructions::{
        batch_update_nullifier_tree::processor::process_batch_update_nullifier_tree,
        create_spl_interface::processor::process_create_spl_interface,
        create_tree::processor::process_create_tree,
        proofless_shield::{process_proofless_shield, process_zone_proofless_shield},
        protocol_config::processor::{
            process_create_protocol_config, process_create_zone_config, process_pause_tree,
            process_update_protocol_config, process_update_zone_config,
            process_update_zone_config_owner,
        },
        transact::process_transact_ix,
    },
};

macro_rules! dispatch {
    (
        $tag:expr, $payload:expr, $program_id:expr, $accounts:expr,
        { $($const:path => $arm:tt),+ $(,)? }
    ) => {
        match $tag {
            $(
                $const => dispatch!(@arm $arm, $payload, $program_id, $accounts),
            )+
            _ => Err(ProgramError::InvalidInstructionData),
        }
    };
    // Handler that parses wincode-encoded instruction data.
    (@arm (wincode $data:ty, $handler:path), $payload:expr, $program_id:expr, $accounts:expr) => {{
        let data = <$data>::deserialize($payload)
            .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
        $handler($program_id, $accounts, data)
    }};
    // Handler that parses typed instruction data.
    (@arm ($data:ty, $handler:path), $payload:expr, $program_id:expr, $accounts:expr) => {{
        let data = <$data>::try_from_slice($payload)
            .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
        $handler($program_id, $accounts, data)
    }};
    // Handler for instructions whose payload is just the tag byte; reject any
    // trailing bytes so the wire format stays exactly one byte.
    (@arm $handler:path, $payload:expr, $program_id:expr, $accounts:expr) => {{
        if !$payload.is_empty() {
            return Err(ShieldedPoolError::InvalidInstructionData.into());
        }
        $handler($program_id, $accounts)
    }};
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (ix_tag, payload) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    if *ix_tag == tag::EMIT_EVENT {
        return Ok(());
    }

    // `transact` parses the raw payload itself (it reads the proof prefix and
    // computes the external-data hash over the trailing bytes), so it does not
    // fit the parse-then-dispatch macro arms.
    if *ix_tag == tag::TRANSACT {
        return process_transact_ix(program_id, accounts, payload);
    }

    dispatch!(*ix_tag, payload, program_id, accounts, {
        tag::CREATE_TREE => (CreateTreeData, process_create_tree),
        tag::BATCH_UPDATE_NULLIFIER_TREE => (BatchUpdateNullifierTreeData, process_batch_update_nullifier_tree),
        tag::PROOFLESS_SHIELD => (wincode ProoflessShieldIxData, process_proofless_shield),
        tag::ZONE_PROOFLESS_SHIELD => (wincode ZoneProoflessShieldIxData, process_zone_proofless_shield),
        tag::CREATE_SPL_INTERFACE => process_create_spl_interface,
        tag::CREATE_PROTOCOL_CONFIG => (CreateProtocolConfigData, process_create_protocol_config),
        tag::UPDATE_PROTOCOL_CONFIG => (UpdateProtocolConfigData, process_update_protocol_config),
        tag::PAUSE_TREE => (PauseTreeData, process_pause_tree),
        tag::CREATE_ZONE_CONFIG => (CreateZoneConfigData, process_create_zone_config),
        tag::UPDATE_ZONE_CONFIG_OWNER => (UpdateZoneConfigOwnerData, process_update_zone_config_owner),
        tag::UPDATE_ZONE_CONFIG => (UpdateZoneConfigData, process_update_zone_config),
    })
}
