//! Custom ring program: proves that the per-transaction viewing secret
//! key of an SPP `transact` is verifiably encrypted to the ring's auditor key,
//! then forwards the transaction to SPP signed with the ring authority PDA.
//!
//! The scope includes confidential transfers, owner preserving merges, Solana
//! eddsa signers, and reader grants. See `custom-rings/program/tests` for the
//! enforced contract.

mod error;
mod instructions;
mod state;

pub use error::CustomRingError;
pub use instructions::NULLIFIER_ROOT_WINDOW;

use custom_ring_interface::{tag, HeadMapRoot, KeyRegistryRoot};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    forward::Forward, process_clear_cosigner_ix, process_clear_spend_window_ix,
    process_create_config_ix, process_create_entry_ix, process_create_indexed_root_ix,
    process_create_policy_ix, process_delegate_transact_ix, process_grant_read_access_ix,
    process_init_spp_ring_config_ix, process_register_key_ix, process_register_spend_ix,
    process_revoke_read_access_ix, process_set_authority_ix, process_set_cosigner_ix,
    process_set_delegate_ix, process_set_deposit_audit_ix, process_set_paused_ix,
    process_set_policy_rules_ix, process_set_policy_source_ix, process_set_spend_window_ix,
    process_transact_ix, process_update_entry_ix,
};

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

    match *ix_tag {
        tag::CREATE_CONFIG => process_create_config_ix(program_id, accounts, ix_data),
        tag::INIT_SPP_RING_CONFIG => process_init_spp_ring_config_ix(program_id, accounts, ix_data),
        tag::TRANSACT => process_transact_ix(program_id, accounts, ix_data),
        // The forwarder passes the tag byte on as well: SPP's dispatcher strips it.
        tag::DEPOSIT => Forward::Deposit.process(program_id, accounts, instruction_data),
        tag::AUDITED_DEPOSIT => {
            Forward::AuditedDeposit.process(program_id, accounts, instruction_data)
        }
        // SPP proves that owner, asset, value, and ring ownership stay unchanged.
        tag::MERGE => Forward::Merge.process(program_id, accounts, instruction_data),
        tag::GRANT_READ_ACCESS => process_grant_read_access_ix(program_id, accounts, ix_data),
        tag::REVOKE_READ_ACCESS => process_revoke_read_access_ix(program_id, accounts, ix_data),
        tag::SET_AUTHORITY => process_set_authority_ix(program_id, accounts, ix_data),
        tag::CREATE_POLICY => process_create_policy_ix(program_id, accounts, ix_data),
        tag::CREATE_ENTRY => process_create_entry_ix(program_id, accounts, ix_data),
        tag::UPDATE_ENTRY => process_update_entry_ix(program_id, accounts, ix_data),
        tag::SET_POLICY_SOURCE => process_set_policy_source_ix(program_id, accounts, ix_data),
        tag::SET_PAUSED => process_set_paused_ix(program_id, accounts, ix_data),
        tag::SET_POLICY_RULES => process_set_policy_rules_ix(program_id, accounts, ix_data),
        tag::SET_CO_SIGNER => process_set_cosigner_ix(program_id, accounts, ix_data),
        tag::CLEAR_CO_SIGNER => process_clear_cosigner_ix(program_id, accounts, ix_data),
        tag::SET_SPEND_WINDOW => process_set_spend_window_ix(program_id, accounts, ix_data),
        tag::CLEAR_SPEND_WINDOW => process_clear_spend_window_ix(program_id, accounts, ix_data),
        tag::SET_DELEGATE => process_set_delegate_ix(program_id, accounts, ix_data),
        tag::SET_DEPOSIT_AUDIT => process_set_deposit_audit_ix(program_id, accounts, ix_data),
        tag::DELEGATE_TRANSACT => process_delegate_transact_ix(program_id, accounts, ix_data),
        tag::REGISTER_SPEND => process_register_spend_ix(program_id, accounts, ix_data),
        tag::CREATE_HEAD_MAP_ROOT => {
            process_create_indexed_root_ix::<HeadMapRoot>(program_id, accounts, ix_data)
        }
        tag::CREATE_KEY_REGISTRY_ROOT => {
            process_create_indexed_root_ix::<KeyRegistryRoot>(program_id, accounts, ix_data)
        }
        tag::REGISTER_KEY => process_register_key_ix(program_id, accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
