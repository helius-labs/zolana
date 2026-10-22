//! Verifies the ring's proofs over an SPP transaction and forwards it signed by the ring PDA.

mod instructions;
mod state;

use custom_ring_interface::{CustomRingError, InstructionTag};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::*;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_tag, ix_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let ix_tag = InstructionTag::try_from(*ix_tag)?;

    match ix_tag {
        InstructionTag::CreateConfig => process_create_config_ix(program_id, accounts, ix_data),
        InstructionTag::InitSppRingConfig => {
            process_init_spp_ring_config_ix(program_id, accounts, ix_data)
        }
        InstructionTag::Transact | InstructionTag::DelegateTransact => {
            process_transact_ix(program_id, accounts, ix_data, ix_tag)
        }
        InstructionTag::Deposit => Err(CustomRingError::DepositAuditRequired.into()),
        // The audited prefix layout starts at the tag byte.
        InstructionTag::AuditedDeposit => {
            process_audited_deposit_ix(program_id, accounts, instruction_data)
        }
        // SPP proves that owner, asset, value and ring ownership stay unchanged.
        InstructionTag::Merge => process_merge_ix(program_id, accounts, ix_data),
        InstructionTag::GrantReadAccess => {
            process_grant_read_access_ix(program_id, accounts, ix_data)
        }
        InstructionTag::RevokeReadAccess => {
            process_revoke_read_access_ix(program_id, accounts, ix_data)
        }
        InstructionTag::SetAuthority => process_set_authority_ix(program_id, accounts, ix_data),
        InstructionTag::CreatePolicy => process_create_policy_ix(program_id, accounts, ix_data),
        InstructionTag::SetPolicySource => {
            process_set_policy_source_ix(program_id, accounts, ix_data)
        }
        InstructionTag::SetPaused => process_set_paused_ix(program_id, accounts, ix_data),
        InstructionTag::SetPolicyRules => {
            process_set_policy_rules_ix(program_id, accounts, ix_data)
        }
        InstructionTag::SetCoSigner => process_set_cosigner_ix(program_id, accounts, ix_data),
        InstructionTag::ClearCoSigner => process_clear_cosigner_ix(program_id, accounts, ix_data),
        InstructionTag::SetDelegate => process_set_delegate_ix(program_id, accounts, ix_data),
        InstructionTag::CreateMemberRegistry => {
            process_create_member_registry_ix(program_id, accounts, ix_data)
        }
        InstructionTag::RegisterKey => process_register_key_ix(program_id, accounts, ix_data),
        InstructionTag::WriteRecords => process_write_records_ix(program_id, accounts, ix_data),
        InstructionTag::AuthorityWriteRecords => {
            process_authority_write_records_ix(program_id, accounts, ix_data)
        }
        InstructionTag::ApplyRecords => process_apply_records_ix(program_id, accounts, ix_data),
        InstructionTag::SetInsertFee => process_set_insert_fee_ix(program_id, accounts, ix_data),
    }
}
