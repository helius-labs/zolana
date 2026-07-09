use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use rings_interface::instruction::{
    instruction_data::transact::TransactIxDataRef, tag::ZONE_AUTHORITY_TRANSACT,
};

use crate::instructions::{
    hash::solana_pk_hash,
    shared::check_not_expired,
    transact::processor::{prepare_proof_inputs, process_transact_core},
    zone_transact::account::ZoneTransactAccounts,
};

/// Zone-authority state transition (freeze, thaw, permanent-delegate transfer).
/// The zone authorizes by signing with its `zone_config` (which must have
/// `zone_authority_transact_is_enabled` set); UTXO owners do not sign. Uses the
/// anonymous owner-tag variant with the zone-authority circuit instantiation that
/// drops the per-owner spend signature.
#[inline(never)]
#[profile]
pub fn process_zone_authority_transact_ix(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix =
        TransactIxDataRef::from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    // IS_AUTHORITY skips the per-owner spend-signature checks; the zone authorizes
    // via the `zone_config` signer. The zone-authority circuit keeps each input
    // owner's `pk_field` private, so `input_owner_pk_hashes` are absent from the
    // public-input hash (see `public_input_hash`) and need no on-chain source.
    let mut proof_inputs = prepare_proof_inputs::<true, true>(accounts, &ix)?;
    let (transact_accounts, zone_program_id) =
        ZoneTransactAccounts::validate_and_parse::<true>(accounts, &ix)?;
    proof_inputs.zone_program_id = solana_pk_hash(&zone_program_id)?;

    process_transact_core::<true, true>(
        &ix,
        &mut proof_inputs,
        transact_accounts,
        clock.slot,
        ZONE_AUTHORITY_TRANSACT,
    )
}
