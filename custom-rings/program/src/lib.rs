//! Minimal custom ring program: proves that the per-transaction viewing secret
//! key of an SPP `transact` is verifiably encrypted to the ring's auditor key,
//! then forwards the transaction to SPP signed with the ring authority PDA.
//!
//! The scope includes confidential transfers, Solana eddsa signers, and reader
//! grants. See `custom-rings/program/tests` for the enforced contract.

mod error;
mod instructions;
mod state;

pub use error::CustomRingError;

use custom_ring_interface::tag;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_create_config_ix, process_deposit_ix, process_grant_read_access_ix,
    process_init_spp_ring_config_ix, process_revoke_read_access_ix, process_set_authority_ix,
    process_transact_ix,
};
use crate::instructions::{
    process_create_policy_ix, process_create_record_ix, process_update_record_ix,
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
        tag::DEPOSIT => process_deposit_ix(program_id, accounts, instruction_data),
        tag::GRANT_READ_ACCESS => process_grant_read_access_ix(program_id, accounts, ix_data),
        tag::REVOKE_READ_ACCESS => process_revoke_read_access_ix(program_id, accounts, ix_data),
        tag::SET_AUTHORITY => process_set_authority_ix(program_id, accounts, ix_data),
        tag::CREATE_POLICY => process_create_policy_ix(program_id, accounts, ix_data),
        tag::CREATE_RECORD => process_create_record_ix(program_id, accounts, ix_data),
        tag::UPDATE_RECORD => process_update_record_ix(program_id, accounts, ix_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
