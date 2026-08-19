//! Minimal custom ring program: proves that the per-transaction viewing secret
//! key of an SPP `transact` is verifiably encrypted to the ring's auditor key,
//! then forwards the transaction to SPP signed with the ring authority PDA.
//!
//! Scope is deliberately minimal: confidential transfers only, Solana eddsa
//! signers only (`CircuitId::RingEddsa`), no smart accounts, no user accounts.
//! Policy is an asset allowlist and a withdrawal rule per asset (open, blocked,
//! or approved by a configured key), set by the ring authority. See `custom-rings/custom_ring.md`.

pub mod error;
pub mod instructions;
pub mod state;
pub mod verifying_keys;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::{
    process_approve_transact_ix, process_create_config_ix, process_deposit_ix,
    process_init_spp_ring_config_ix, process_revoke_approval_ix, process_set_policy_ix,
    process_transact_ix,
};

pub mod tag {
    pub const CREATE_CONFIG: u8 = 1;
    pub const INIT_SPP_RING_CONFIG: u8 = 2;
    pub const TRANSACT: u8 = 3;
    pub const SET_POLICY: u8 = 4;
    pub const APPROVE_TRANSACT: u8 = 5;
    pub const REVOKE_APPROVAL: u8 = 6;
    /// Ring deposits carry no proof and are forwarded to SPP byte for byte, so
    /// the dispatcher matches SPP's own deposit tag instead of a program-local
    /// one: the client builds the SPP-shaped instruction and only re-targets the
    /// program id.
    pub const DEPOSIT: u8 = zolana_interface::instruction::tag::RING_DEPOSIT;
}

pub const CONFIG_PDA_SEED: &[u8] = b"config";

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

// `declare_id!` of the build-time program id, see `build.rs`.
include!(concat!(env!("OUT_DIR"), "/program_id.rs"));

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (ix_tag, ix_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *ix_tag {
        tag::CREATE_CONFIG => process_create_config_ix(accounts, ix_data),
        tag::INIT_SPP_RING_CONFIG => process_init_spp_ring_config_ix(accounts, ix_data),
        tag::TRANSACT => process_transact_ix(accounts, ix_data),
        tag::SET_POLICY => process_set_policy_ix(accounts, ix_data),
        tag::APPROVE_TRANSACT => process_approve_transact_ix(accounts, ix_data),
        tag::REVOKE_APPROVAL => process_revoke_approval_ix(accounts, ix_data),
        // The forwarder passes the tag byte on as well: SPP's dispatcher strips it.
        tag::DEPOSIT => process_deposit_ix(accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
