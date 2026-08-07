//! Test policy-ring program for shielded-pool integration tests.
//!
//! It enforces no policy: every supported ring instruction is forwarded verbatim
//! to SPP, signed with the ring's `ring_auth` PDA. This exists so integration
//! tests can exercise the ring-signer path (a PDA can only sign via a CPI from
//! its owning program). The client builds the SPP-shaped instruction (the ring
//! `program_id` and `ring_auth` account are identical between the call to this
//! fixture and the CPI it makes), so the fixture only re-targets the program id
//! and marks `ring_auth` a signer.

use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{instruction::tag, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let Some(ix_tag) = data.first() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match *ix_tag {
        tag::CREATE_RING_CONFIG
        | tag::RING_DEPOSIT
        | tag::RING_TRANSACT
        | tag::RING_AUTHORITY_TRANSACT
        | tag::RING_MERGE_TRANSACT
        | tag::AGGREGATE_TRANSACT => forward_to_spp(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Transact fixes the SPP account at index 3 but the other forwarded families
/// keep their own layouts, so this shared forwarder locates the SPP account by
/// address. The forwarded data keeps the tag because SPP's dispatcher strips it.
fn forward_to_spp(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let (ring_auth, bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], program_id);
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if !accounts.iter().any(|a| a.address() == &spp_id) {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !accounts.iter().any(|a| a.address() == &ring_auth) {
        return Err(ProgramError::InvalidSeeds);
    }

    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|a| {
            let is_signer = a.is_signer() || a.address() == &ring_auth;
            InstructionAccount::new(a.address(), a.is_writable(), is_signer)
        })
        .collect();
    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data,
    };
    let bump = [bump];
    let seeds = [Seed::from(RING_AUTH_PDA_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    // A five-mint ring deposit carries the fixed prefix, ring_auth, and five
    // SPL settlement groups.
    invoke_signed_with_bounds::<32, _>(&instruction, accounts, core::slice::from_ref(&signer))
}
