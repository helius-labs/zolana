//! Test program that forwards a `transact` instruction to SPP via CPI, signing
//! with its CPI-signer PDA, so integration tests can exercise a
//! program-governed transact.

use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{instruction::tag, CPI_SIGNER_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};

pub const CPI_TEST_PROGRAM_ID: [u8; 32] = *b"cpi__test_program_aaaaaaaaaaaaaa";

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
        tag::TRANSACT => forward_to_spp(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Forward a `transact` instruction to SPP verbatim, signing this program's
/// CPI-signer PDA. We rebuild the SPP instruction from the received account
/// views, flip the CPI-signer account to a signer, and forward the data (tag
/// included, as SPP's dispatcher strips it) unchanged.
fn forward_to_spp(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let (cpi_signer, bump) = Address::find_program_address(&[CPI_SIGNER_PDA_SEED], program_id);
    // The last account is the SPP program account (loadable for the emit_event
    // self-CPI), matching the builders' account layout.
    let spp = accounts.last().ok_or(ProgramError::NotEnoughAccountKeys)?;
    check_shielded_pool(spp.address())?;
    if !accounts.iter().any(|a| a.address() == &cpi_signer) {
        return Err(ProgramError::InvalidSeeds);
    }

    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|a| {
            let is_signer = a.is_signer() || a.address() == &cpi_signer;
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
    let seeds = [Seed::from(CPI_SIGNER_PDA_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    invoke_signed_with_bounds::<32, _>(&instruction, accounts, core::slice::from_ref(&signer))
}

fn check_shielded_pool(account: &Address) -> Result<(), ProgramError> {
    if account != &Address::from(SHIELDED_POOL_PROGRAM_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
