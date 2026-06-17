pub mod instructions;

use borsh::BorshDeserialize;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::error::ShieldedPoolError;
use zolana_interface::instruction::{
    tag::InstructionTag, BatchUpdateNullifierTreeData, CreateProtocolConfigData, CreateTreeData,
    CreateZoneConfigData, PauseTreeData, ProoflessShieldIxData, UpdateProtocolConfigData,
    UpdateZoneConfigData, UpdateZoneConfigOwnerData, ZoneProoflessShieldIxData,
};

use crate::instructions::{
    batch_update_nullifier_tree::process_batch_update_nullifier_tree,
    create_asset_counter::process_create_asset_counter,
    create_spl_interface::processor::process_create_spl_interface,
    create_tree::process_create_tree,
    deposit::{process_proofless_shield, process_zone_proofless_shield},
    protocol_config::{
        create::process_create_protocol_config, pause_tree::process_pause_tree,
        update::process_update_protocol_config,
    },
    transact::process_transact_ix,
    zone_config::{
        create::process_create_zone_config, update::process_update_zone_config,
        update_owner::process_update_zone_config_owner,
    },
};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
pinocchio::address::declare_id!("8nhL4dQgcddkc8cNV5piaZ1zKGowap1XrS8EDKi4rywq");

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

    let ix_tag =
        InstructionTag::try_from(*ix_tag).map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix_tag {
        InstructionTag::EmitEvent => Ok(()),
        InstructionTag::Transact => process_transact_ix(program_id, accounts, payload),
        InstructionTag::CreateTree => {
            let data = CreateTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_tree(accounts, data)
        }
        InstructionTag::BatchUpdateNullifierTree => {
            let data = BatchUpdateNullifierTreeData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_batch_update_nullifier_tree(program_id, accounts, data)
        }
        InstructionTag::ProoflessShield => {
            let data = ProoflessShieldIxData::deserialize(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_proofless_shield(program_id, accounts, data)
        }
        InstructionTag::ZoneProoflessShield => {
            let data = ZoneProoflessShieldIxData::deserialize(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_zone_proofless_shield(program_id, accounts, data)
        }
        InstructionTag::CreateAssetCounter => {
            if !payload.is_empty() {
                return Err(ShieldedPoolError::InvalidInstructionData.into());
            }
            process_create_asset_counter(program_id, accounts)
        }
        InstructionTag::CreateSplInterface => {
            if !payload.is_empty() {
                return Err(ShieldedPoolError::InvalidInstructionData.into());
            }
            process_create_spl_interface(program_id, accounts)
        }
        InstructionTag::CreateProtocolConfig => {
            let data = *bytemuck::try_from_bytes::<CreateProtocolConfigData>(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_protocol_config(program_id, accounts, data)
        }
        InstructionTag::UpdateProtocolConfig => {
            let data = UpdateProtocolConfigData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_update_protocol_config(accounts, data)
        }
        InstructionTag::PauseTree => {
            let data = *bytemuck::try_from_bytes::<PauseTreeData>(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_pause_tree(accounts, data)
        }
        InstructionTag::CreateZoneConfig => {
            let data = CreateZoneConfigData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_create_zone_config(program_id, accounts, data)
        }
        InstructionTag::UpdateZoneConfigOwner => {
            let data = UpdateZoneConfigOwnerData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_update_zone_config_owner(accounts, data)
        }
        InstructionTag::UpdateZoneConfig => {
            let data = UpdateZoneConfigData::try_from_slice(payload)
                .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
            process_update_zone_config(accounts, data)
        }
    }
}
