pub mod instructions;

use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::instruction::tag::InstructionTag;

use crate::instructions::{
    batch_queue::{
        process_apply_batch_ix, process_close_batch_queue_ix, process_create_batch_queue_ix,
        process_enqueue_transact_ix, process_execute_batch_verify_ix,
    },
    batch_update_nullifier_tree::{
        process_batch_update_nullifier_tree, process_batch_update_nullifier_tree_many,
    },
    create_asset_counter::process_create_asset_counter,
    create_spl_interface::processor::process_create_spl_interface,
    create_tree::process_create_tree,
    deposit::{process_deposit, process_zone_deposit},
    merge::process_merge_transact_ix,
    merge_zone::process_merge_zone_ix,
    protocol_config::{
        create::process_create_protocol_config, pause_tree::process_pause_tree,
        update::process_update_protocol_config,
    },
    transact::{process_batch_transact_ix, process_transact_ix},
    zone_config::{
        create::process_create_zone_config, update::process_update_zone_config,
        update_owner::process_update_zone_config_owner,
    },
};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
pinocchio::address::declare_id!("sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA");

#[profile]
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
        // Deliberate no-op: the event self-CPI exists only to record inner-
        // instruction data. Anyone can invoke this tag (directly or via CPI)
        // with forged bytes; indexers MUST filter events by parent instruction
        // (see `zolana_event::tag::EMIT_EVENT`).
        InstructionTag::EmitEvent => Ok(()),
        InstructionTag::Transact
        | InstructionTag::ZoneTransact
        | InstructionTag::ZoneAuthorityTransact => process_transact_ix(accounts, payload, ix_tag),
        InstructionTag::BatchTransact => process_batch_transact_ix(accounts, payload),
        InstructionTag::CreateBatchQueue => process_create_batch_queue_ix(accounts, payload),
        InstructionTag::EnqueueTransact => process_enqueue_transact_ix(accounts, payload),
        InstructionTag::ExecuteBatchVerify => process_execute_batch_verify_ix(accounts),
        InstructionTag::ApplyBatch => process_apply_batch_ix(accounts),
        InstructionTag::CloseBatchQueue => process_close_batch_queue_ix(accounts),
        InstructionTag::CreateTree => process_create_tree(accounts, payload),
        InstructionTag::BatchUpdateNullifierTree => {
            process_batch_update_nullifier_tree(accounts, payload)
        }
        InstructionTag::BatchUpdateNullifierTreeMany => {
            process_batch_update_nullifier_tree_many(accounts, payload)
        }
        InstructionTag::Deposit => process_deposit(accounts, payload),
        InstructionTag::ZoneDeposit => process_zone_deposit(accounts, payload),
        InstructionTag::CreateAssetCounter => process_create_asset_counter(accounts, payload),
        InstructionTag::CreateSplInterface => process_create_spl_interface(accounts, payload),
        InstructionTag::CreateProtocolConfig => process_create_protocol_config(accounts, payload),
        InstructionTag::UpdateProtocolConfig => process_update_protocol_config(accounts, payload),
        InstructionTag::PauseTree => process_pause_tree(accounts, payload),
        InstructionTag::CreateZoneConfig => process_create_zone_config(accounts, payload),
        InstructionTag::UpdateZoneConfigOwner => {
            process_update_zone_config_owner(accounts, payload)
        }
        InstructionTag::UpdateZoneConfig => process_update_zone_config(accounts, payload),
        InstructionTag::MergeTransact => process_merge_transact_ix(accounts, payload),
        InstructionTag::ZoneMergeTransact => process_merge_zone_ix(accounts, payload),
    }
}
