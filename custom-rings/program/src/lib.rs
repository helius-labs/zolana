//! Custom ring program: verifies the ring's proof over an SPP transaction,
//! then forwards it to SPP signed by the ring authority PDA.

mod instructions;
mod state;

use custom_ring_interface::InstructionTag;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{forward::Forward, *};

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
    let ix_tag =
        InstructionTag::try_from(*ix_tag).map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix_tag {
        InstructionTag::CreateConfig => process_create_config_ix(program_id, accounts, ix_data),
        InstructionTag::InitSppRingConfig => {
            process_init_spp_ring_config_ix(program_id, accounts, ix_data)
        }
        InstructionTag::Transact => process_transact_ix(program_id, accounts, ix_data),
        // SPP's dispatcher strips the tag byte, the forwarder passes it on.
        InstructionTag::Deposit => Forward::Deposit.process(program_id, accounts, instruction_data),
        InstructionTag::AuditedDeposit => {
            Forward::AuditedDeposit.process(program_id, accounts, instruction_data)
        }
        // SPP proves that owner, asset, value and ring ownership stay unchanged.
        InstructionTag::Merge => Forward::Merge.process(program_id, accounts, instruction_data),
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
        InstructionTag::SetDepositAudit => {
            process_set_deposit_audit_ix(program_id, accounts, ix_data)
        }
        InstructionTag::DelegateTransact => {
            process_delegate_transact_ix(program_id, accounts, ix_data)
        }
        InstructionTag::CreateMemberRegistryRoot => {
            process_create_member_registry_root_ix(program_id, accounts, ix_data)
        }
        InstructionTag::RegisterKey => process_register_key_ix(program_id, accounts, ix_data),
        InstructionTag::UpdateMembers => process_update_members_ix(program_id, accounts, ix_data),
    }
}
