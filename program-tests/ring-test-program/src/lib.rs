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
        | tag::RING_MERGE_TRANSACT => forward_to_spp(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Forward a ring instruction to SPP verbatim, signing the ring's `ring_auth`
/// PDA. The client lays out the same accounts for the call into this fixture and
/// for the CPI into SPP (only the target program id and the `ring_auth` signer
/// flag differ). Transact fixes the SPP account at index 3, while the other
/// forwarded instruction families retain their own layouts, so this shared
/// forwarder locates the SPP account by address. We rebuild the SPP instruction
/// from the received account views, flip the `ring_auth` account to a signer, and
/// forward the data (tag included, as SPP's dispatcher strips it) unchanged.
fn forward_to_spp(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let (ring_auth, bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], program_id);
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let spp = accounts
        .iter()
        .find(|account| account.address() == &spp_id)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    check_shielded_pool(spp.address())?;
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
    invoke_signed_with_bounds::<24, _>(&instruction, accounts, core::slice::from_ref(&signer))
}

fn check_shielded_pool(account: &Address) -> Result<(), ProgramError> {
    if account != &Address::from(SHIELDED_POOL_PROGRAM_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
