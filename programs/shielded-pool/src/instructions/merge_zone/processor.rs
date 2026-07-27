use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{merge_transact::MergeExternalDataHash, merge_zone::MergeZoneIxDataRef},
        tag::ZONE_MERGE_TRANSACT,
    },
};

use super::account::MergeZoneAccounts;
use crate::instructions::{
    hash::solana_pk_hash,
    merge::{processor::process_merge_core, verify::MergeOwnerBinding},
    shared::check_not_expired,
};

/// Policy-zone analog of `merge_transact`, invoked via CPI from a zone program.
/// The zone's `zone_config` account signs (authorization), the merged output is
/// indexed by the first input nullifier, and SPP does not check
/// `protocol_config.merge_authorities`.
#[inline(never)]
pub fn process_merge_zone_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        MergeZoneIxDataRef::from_bytes(data).map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
    let merge = &ix.merge;
    let clock = Clock::get()?;
    check_not_expired(merge.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeZoneAccounts::validate_and_parse(accounts)?;

    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: ZONE_MERGE_TRANSACT,
        expiry_unix_ts: merge.expiry_unix_ts,
        output_utxo_hash: merge.output_utxo_hash,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    // The zone merge proof binds `zone_program_id` from the signing `zone_config`
    // and the output `zone_data_hash` the zone program selected, and is verified
    // against the `merge_zone_8_1` key. A policy zone has no `user_record`
    // registry, so the `Zone` binding omits owner identity entirely (see
    // `MergeProof::public_input_hash`); the binding also selects the
    // `merge_zone_8_1` verifying key.
    let zone_program_id = solana_pk_hash(merge_accounts.zone_program_id.as_array())?;
    let owner_binding = MergeOwnerBinding::Zone {
        zone_program_id,
        output_zone_data_hash: *ix.output_zone_data_hash,
    };

    // The merged output is indexed by the first input nullifier. The output
    // `zone_data_hash` is published in the event so the wallet can reconstruct
    // the zone output.
    process_merge_core(
        merge_accounts.input_tree,
        merge_accounts.output_tree,
        merge_accounts.payer,
        merge,
        external_data_hash,
        owner_binding,
        *merge
            .nullifiers
            .first()
            .ok_or(ShieldedPoolError::InvalidMergeShape)?,
        ix.output_zone_data_hash.to_vec(),
    )
}
