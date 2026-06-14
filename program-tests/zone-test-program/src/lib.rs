//! Test policy-zone program for litesvm.
//!
//! Pinocchio-based: built against `solana-program`'s entrypoint ABI this
//! program crashed litesvm 0.12's loader during entrypoint deserialization
//! (access violation before any CPI). Pinocchio's entrypoint is ABI-compatible
//! with the loader the SPP program already uses, so this fixture matches it.

use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{instruction::tag, SHIELDED_POOL_PROGRAM_ID};

const ZONE_AUTH_SEED: &[u8] = b"zone_auth";
const TREE: usize = 0;
const PAYER: usize = 1;
const ZONE_AUTH: usize = 2;
const SYSTEM_PROGRAM: usize = 3;
const CPI_AUTHORITY: usize = 4;
const USER_SOL: usize = 5;
const SHIELDED_POOL_PROGRAM: usize = 6;
const FORWARDED_ACCOUNTS: usize = 7;

const CREATE_ZONE_PAYER: usize = 0;
const CREATE_ZONE_CONFIG: usize = 1;
const CREATE_ZONE_AUTH: usize = 2;
const CREATE_ZONE_SYSTEM: usize = 3;
const CREATE_ZONE_SHIELDED_POOL_PROGRAM: usize = 4;
const CREATE_ZONE_ACCOUNTS: usize = 5;

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
        tag::CREATE_ZONE_CONFIG => process_create_zone_config(program_id, accounts, data),
        tag::ZONE_PROOFLESS_SHIELD => process_zone_proofless_shield(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_create_zone_config(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let accounts = accounts
        .get(..CREATE_ZONE_ACCOUNTS)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (zone_auth, bump) = Address::find_program_address(&[ZONE_AUTH_SEED], program_id);
    if accounts[CREATE_ZONE_AUTH].address() != &zone_auth {
        return Err(ProgramError::InvalidSeeds);
    }
    check_shielded_pool(accounts[CREATE_ZONE_SHIELDED_POOL_PROGRAM].address())?;

    let metas = [
        InstructionAccount::writable_signer(accounts[CREATE_ZONE_PAYER].address()),
        InstructionAccount::writable(accounts[CREATE_ZONE_CONFIG].address()),
        InstructionAccount::readonly_signer(&zone_auth),
        InstructionAccount::readonly(accounts[CREATE_ZONE_SYSTEM].address()),
    ];
    let instruction = InstructionView {
        program_id: &Address::from(SHIELDED_POOL_PROGRAM_ID),
        accounts: &metas,
        data,
    };
    let bump = [bump];
    let seeds = [Seed::from(ZONE_AUTH_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    invoke_signed(
        &instruction,
        &[
            &accounts[CREATE_ZONE_PAYER],
            &accounts[CREATE_ZONE_CONFIG],
            &accounts[CREATE_ZONE_AUTH],
            &accounts[CREATE_ZONE_SYSTEM],
        ],
        core::slice::from_ref(&signer),
    )
}

fn process_zone_proofless_shield(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let accounts = accounts
        .get(..FORWARDED_ACCOUNTS)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (zone_auth, bump) = Address::find_program_address(&[ZONE_AUTH_SEED], program_id);
    if accounts[ZONE_AUTH].address() != &zone_auth {
        return Err(ProgramError::InvalidSeeds);
    }
    check_shielded_pool(accounts[SHIELDED_POOL_PROGRAM].address())?;

    let metas = [
        InstructionAccount::writable(accounts[TREE].address()),
        InstructionAccount::writable_signer(accounts[PAYER].address()),
        InstructionAccount::readonly_signer(&zone_auth),
        InstructionAccount::readonly(accounts[SYSTEM_PROGRAM].address()),
        InstructionAccount::writable(accounts[CPI_AUTHORITY].address()),
        InstructionAccount::writable(accounts[USER_SOL].address()),
        InstructionAccount::readonly(accounts[SHIELDED_POOL_PROGRAM].address()),
    ];
    let instruction = InstructionView {
        program_id: &Address::from(SHIELDED_POOL_PROGRAM_ID),
        accounts: &metas,
        data,
    };
    let bump = [bump];
    let seeds = [Seed::from(ZONE_AUTH_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    invoke_signed(
        &instruction,
        &[
            &accounts[TREE],
            &accounts[PAYER],
            &accounts[ZONE_AUTH],
            &accounts[SYSTEM_PROGRAM],
            &accounts[CPI_AUTHORITY],
            &accounts[USER_SOL],
            &accounts[SHIELDED_POOL_PROGRAM],
        ],
        core::slice::from_ref(&signer),
    )
}

fn check_shielded_pool(account: &Address) -> Result<(), ProgramError> {
    if account != &Address::from(SHIELDED_POOL_PROGRAM_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
