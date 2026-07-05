//! Squads zone on-chain program (pinocchio). Verifies the zone and
//! key-encryption proofs, manages zone accounts, and CPIs the SPP.
//!
//! The entrypoint, dispatch, and shared helpers live here; instruction
//! processors are under `instructions/`.

pub mod instructions;
pub mod shared;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
use zolana_squads_interface::instruction::tag::InstructionTag;

use crate::instructions::{
    process_cancel_key_update_ix, process_cancel_proposal_ix, process_close_viewing_key_account_ix,
    process_create_proposal_ix, process_create_viewing_key_account_ix,
    process_create_zone_config_ix, process_deposit_ix, process_execute_key_update_ix,
    process_execute_proposal_ix, process_fill_key_update_ix, process_full_withdrawal_ix,
    process_init_spp_zone_config_ix, process_merge_transact_ix,
    process_toggle_viewing_key_account_ix, process_transact_ix,
    process_update_viewing_key_account_ix, process_update_zone_config_ix,
};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}
pinocchio::address::declare_id!("62EpnphqgmKwc1x9nfnLVvxGBNF8cdkrfvWPnY5VECAo");

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (ix_tag, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let ix_tag =
        InstructionTag::try_from(*ix_tag).map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix_tag {
        InstructionTag::Transact => process_transact_ix(accounts, data),
        InstructionTag::Deposit => process_deposit_ix(accounts, data),
        InstructionTag::MergeTransact => process_merge_transact_ix(accounts, data),
        InstructionTag::CreateZoneConfig => process_create_zone_config_ix(accounts, data),
        InstructionTag::UpdateZoneConfig => process_update_zone_config_ix(accounts, data),
        InstructionTag::CreateViewingKeyAccount => {
            process_create_viewing_key_account_ix(accounts, data)
        }
        InstructionTag::UpdateViewingKeyAccount => {
            process_update_viewing_key_account_ix(accounts, data)
        }
        InstructionTag::FillKeyUpdate => process_fill_key_update_ix(accounts, data),
        InstructionTag::CloseViewingKeyAccount => {
            process_close_viewing_key_account_ix(accounts, data)
        }
        InstructionTag::ToggleViewingKeyAccount => {
            process_toggle_viewing_key_account_ix(accounts, data)
        }
        InstructionTag::FullWithdrawal => process_full_withdrawal_ix(accounts, data),
        InstructionTag::CreateProposal => process_create_proposal_ix(accounts, data),
        InstructionTag::CancelProposal => process_cancel_proposal_ix(accounts, data),
        InstructionTag::ExecuteProposal => process_execute_proposal_ix(accounts, data),
        InstructionTag::ExecuteKeyUpdate => process_execute_key_update_ix(accounts, data),
        InstructionTag::CancelKeyUpdate => process_cancel_key_update_ix(accounts, data),
        InstructionTag::InitSppZoneConfig => process_init_spp_zone_config_ix(accounts, data),
    }
}
