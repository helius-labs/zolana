use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            merge_transact::{
                MergeExternalDataHash, MERGE_ENCRYPTED_UTXO_TYPE_PREFIX, MERGE_INPUT_COUNT,
            },
            merge_zone::MergeZoneIxDataRef,
        },
        tag::ZONE_MERGE_TRANSACT,
    },
};

use super::account::MergeZoneAccounts;
use crate::instructions::{
    hash::address_field,
    merge::{
        processor::process_merge_core,
        verify::{MergeOwnerBinding, MergeProofInputs},
    },
    shared::check_not_expired,
};

/// Policy-zone analog of `merge_transact`, invoked via CPI from a zone program.
/// The zone's `zone_config` account signs (authorization), the merged output is
/// indexed by the single-use `merge_view_tag`, and SPP does not check
/// `protocol_config.merge_authorities`.
#[inline(never)]
pub fn process_merge_zone_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        MergeZoneIxDataRef::from_bytes(data).map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
    let merge = &ix.merge;
    let merge_view_tag = *ix.merge_view_tag;

    if merge.encrypted_utxo.first() != Some(&MERGE_ENCRYPTED_UTXO_TYPE_PREFIX) {
        return Err(ShieldedPoolError::InvalidMergeOutputScheme.into());
    }

    let clock = Clock::get()?;
    check_not_expired(merge.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeZoneAccounts::validate_and_parse(accounts)?;

    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: ZONE_MERGE_TRANSACT,
        expiry_unix_ts: merge.expiry_unix_ts,
        output_utxo_hash: merge.output_utxo_hash,
        encrypted_utxo: merge.encrypted_utxo,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    // The zone merge proof binds `zone_program_id` from the signing `zone_config`
    // and is verified against the `merge_zone_8_1` key. A policy zone has no
    // `user_record` registry, so the `Zone` binding omits owner identity entirely
    // (see `MergeProof::public_input_hash`); the binding also selects the
    // `merge_zone_8_1` verifying key.
    let zone_program_id = address_field(merge_accounts.zone_program_id.as_array())?;
    let derived = MergeProofInputs {
        utxo_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
        nullifier_tree_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
        external_data_hash,
        owner_binding: MergeOwnerBinding::Zone { zone_program_id },
    };

    // The merged output is indexed by the single-use `merge_view_tag`, which is
    // also inserted into the nullifier queue for replay protection.
    process_merge_core(
        merge_accounts.tree,
        merge,
        derived,
        merge_view_tag,
        clock.slot,
        Some(merge_view_tag),
    )
}
