//! Test-only "policy zone" program.
//!
//! Forwards a `zone_proofless_shield` call to the shielded pool, signing with
//! its `zone_auth` PDA (seed `b"zone_auth"`). It enforces no policy; it exists
//! only so integration tests can drive the zone-signer path, since a `zone_auth`
//! PDA can sign for the pool only through a CPI from its owning program.
//!
//! Accounts (forwarded 1:1 to the shielded pool, with `zone_auth` signed by
//! this program): `[tree, payer, zone_auth, system_program, cpi_authority,
//! user_sol, shielded_pool_program]`.
//!
//! Instruction data: the shielded-pool `zone_proofless_shield` instruction
//! bytes (tag + borsh `ZoneProoflessShieldIxData`), built by the caller with
//! `cpi_signer = (this program id, zone_auth bump)`. Forwarded verbatim.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    pubkey::Pubkey,
};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;

const ZONE_AUTH_SEED: &[u8] = b"zone_auth";

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let (zone_auth, bump) = Pubkey::find_program_address(&[ZONE_AUTH_SEED], program_id);
    let shielded_pool = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    // Re-emit the call to the shielded pool with `zone_auth` (account 2) as the
    // CPI signer. Writable/signer flags mirror the proofless SOL deposit layout.
    let metas = vec![
        AccountMeta::new(*accounts[0].key, false),          // tree
        AccountMeta::new(*accounts[1].key, true),           // payer
        AccountMeta::new_readonly(zone_auth, true),         // zone_auth (PDA signer)
        AccountMeta::new_readonly(*accounts[3].key, false), // system program
        AccountMeta::new(*accounts[4].key, false),          // cpi_authority (SOL vault)
        AccountMeta::new(*accounts[5].key, false),          // user_sol (== payer)
        AccountMeta::new_readonly(*accounts[6].key, false), // shielded_pool_program
    ];
    let ix = Instruction {
        program_id: shielded_pool,
        accounts: metas,
        data: data.to_vec(),
    };
    invoke_signed(&ix, accounts, &[&[ZONE_AUTH_SEED, &[bump]]])
}
