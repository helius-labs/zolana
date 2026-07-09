//! Test policy-zone program for shielded-pool integration tests.
//!
//! It enforces no policy: every supported zone instruction is forwarded verbatim
//! to SPP, signed with the zone's `zone_auth` PDA. This exists so integration
//! tests can exercise the zone-signer path (a PDA can only sign via a CPI from
//! its owning program). The client builds the SPP-shaped instruction (the zone
//! `program_id` and `zone_auth` account are identical between the call to this
//! fixture and the CPI it makes), so the fixture only re-targets the program id
//! and marks `zone_auth` a signer.

use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use rings_interface::{instruction::tag, SHIELDED_POOL_PROGRAM_ID, ZONE_AUTH_PDA_SEED};

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
        tag::CREATE_ZONE_CONFIG
        | tag::ZONE_DEPOSIT
        | tag::ZONE_TRANSACT
        | tag::ZONE_AUTHORITY_TRANSACT
        | tag::ZONE_MERGE_TRANSACT => forward_to_spp(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Forward a zone instruction to SPP verbatim, signing the zone's `zone_auth`
/// PDA. The client lays out the same accounts for the call into this fixture and
/// for the CPI into SPP (only the target program id and the `zone_auth` signer
/// flag differ), and the SPP program account is passed last. We rebuild the SPP
/// instruction from the received account views, flip the `zone_auth` account to a
/// signer, and forward the data (tag included, as SPP's dispatcher strips it)
/// unchanged.
fn forward_to_spp(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let (zone_auth, bump) = Address::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id);
    // The last account is the SPP program account (loadable for the emit_event
    // self-CPI), matching the builders' account layout.
    let spp = accounts.last().ok_or(ProgramError::NotEnoughAccountKeys)?;
    check_shielded_pool(spp.address())?;
    if !accounts.iter().any(|a| a.address() == &zone_auth) {
        return Err(ProgramError::InvalidSeeds);
    }

    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|a| {
            let is_signer = a.is_signer() || a.address() == &zone_auth;
            InstructionAccount::new(a.address(), a.is_writable(), is_signer)
        })
        .collect();
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data,
    };
    let bump = [bump];
    let seeds = [Seed::from(ZONE_AUTH_PDA_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    invoke_signed_with_bounds::<16, _>(&instruction, accounts, core::slice::from_ref(&signer))
}

fn check_shielded_pool(account: &Address) -> Result<(), ProgramError> {
    if account != &Address::from(SHIELDED_POOL_PROGRAM_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
