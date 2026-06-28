use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::instruction::{instruction_data::transact::TransactIxDataRef, tag::ZONE_TRANSACT};

use super::account::ZoneTransactAccounts;
use crate::instructions::{
    hash::solana_pk_hash,
    shared::check_not_expired,
    transact::processor::{prepare_proof_inputs, process_transact_core},
};

/// Anonymous policy-zone analog of `transact`. The `ZoneConfig` account (the
/// zone's `zone_auth` PDA) signs; SPP binds `pk_field(ZoneConfig.program_id)` as
/// the proof's `zone_program_id`, selects the anonymous verifying keys, and
/// otherwise runs the shared transact flow.
#[inline(never)]
#[profile]
pub fn process_zone_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let mut proof_inputs = prepare_proof_inputs::<true, false>(accounts, &ix)?;
    let (transact_accounts, zone_program_id) =
        ZoneTransactAccounts::validate_and_parse::<false>(accounts, &ix)?;
    proof_inputs.zone_program_id = solana_pk_hash(&zone_program_id)?;

    process_transact_core::<true, false>(
        &ix,
        proof_inputs,
        transact_accounts,
        clock.slot,
        ZONE_TRANSACT,
    )
}
