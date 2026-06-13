//! Test-only policy-zone wrapper.
//!
//! It forwards SPP instruction bytes and signs with this program's `zone_auth`
//! PDA, letting integration tests exercise zone signer validation.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

const ZONE_AUTH_SEED: &[u8] = b"zone_auth";
const TREE: usize = 0;
const PAYER: usize = 1;
const ZONE_AUTH: usize = 2;
const SYSTEM_PROGRAM: usize = 3;
const CPI_AUTHORITY: usize = 4;
const USER_SOL: usize = 5;
const SHIELDED_POOL_PROGRAM: usize = 6;
const FORWARDED_ACCOUNTS: usize = 7;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts = accounts
        .get(..FORWARDED_ACCOUNTS)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (zone_auth, bump) = Pubkey::find_program_address(&[ZONE_AUTH_SEED], program_id);
    let shielded_pool = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    if *accounts[ZONE_AUTH].key != zone_auth {
        return Err(ProgramError::InvalidSeeds);
    }
    if *accounts[SHIELDED_POOL_PROGRAM].key != shielded_pool {
        return Err(ProgramError::IncorrectProgramId);
    }

    let metas = vec![
        AccountMeta::new(*accounts[TREE].key, false),
        AccountMeta::new(*accounts[PAYER].key, true),
        AccountMeta::new_readonly(zone_auth, true),
        AccountMeta::new_readonly(*accounts[SYSTEM_PROGRAM].key, false),
        AccountMeta::new(*accounts[CPI_AUTHORITY].key, false),
        AccountMeta::new(*accounts[USER_SOL].key, false),
        AccountMeta::new_readonly(*accounts[SHIELDED_POOL_PROGRAM].key, false),
    ];
    let ix = Instruction {
        program_id: shielded_pool,
        accounts: metas,
        data: data.to_vec(),
    };
    invoke_signed(&ix, accounts, &[&[ZONE_AUTH_SEED, &[bump]]])
}
