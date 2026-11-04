use crate::instructions::shared::caused_by;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use spr_hasher::primitives::{hash_bytes, solana_owner_identity};
use spr_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::{
        merge_ring::{MergeRingIxDataRef, MergeRingV2IxDataRef},
        merge_transact::MergeTransactIxDataRef,
        MergeRingAuthority,
    },
};

use super::account::MergeRingAccounts;
use crate::instructions::{
    merge::{
        cache::load_merge_cache,
        processor::{process_merge_core, validate_field_elements, MergeCoreAccounts},
        verify::MergeOwnerBinding,
    },
    shared::{check_field_element, check_not_expired},
};

/// Policy-ring analog of `merge_transact`, invoked via CPI from a ring program.
/// The ring's `ring_config` account signs (authorization), the merged output is
/// indexed by the first input nullifier, and SPP does not check
/// `protocol_config.merge_authorities`.
#[inline(never)]
pub fn process_merge_ring_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeRingIxDataRef::from_bytes(data)
        .map_err(caused_by(ShieldedPoolError::InvalidMergeShape))?;
    let merge = &ix.merge;
    let clock = check_ring_merge_data(merge, ix.output_ring_data_hash)?;

    let merge_accounts = MergeRingAccounts::validate_and_parse(
        accounts,
        merge.nullifiers.len(),
        merge.cache_slot,
        MergeRingAuthority::Ring,
    )?;
    // The ring merge proof binds `ring_program_id` from the signing `ring_config`
    // and the output `ring_data_hash` the ring program selected, and is verified
    // against the `merge_ring_<n_inputs>_1` key. A policy ring has no
    // `user_record` registry, so the `Ring` binding omits owner identity entirely
    // (see `MergeProof::public_input_hash`); the binding and the declared input
    // count select the verifying key. The proof does not bind
    // `merge.output_encryption`; the indexer publishes it unverified.
    let owner_binding = MergeOwnerBinding::Ring {
        ring_program_id: hash_bytes(merge_accounts.ring_program_id.as_array())?,
        output_ring_data_hash: *ix.output_ring_data_hash,
    };
    let output_view_tag = first_nullifier(merge)?;
    finish_ring_merge(
        merge_accounts,
        merge,
        owner_binding,
        output_view_tag,
        &clock,
    )
}

/// Under [`MergeRingAuthority::OwnerSigned`] the proof publishes the signer's
/// hashed key, so an opening alone admits no merge.
#[inline(never)]
pub fn process_merge_ring_v2_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeRingV2IxDataRef::from_bytes(data)
        .map_err(caused_by(ShieldedPoolError::InvalidMergeShape))?;
    let merge = &ix.merge;
    if !merge.output_encryption.is_canonical() {
        return Err(ShieldedPoolError::NonCanonicalMergeCiphertext.into());
    }
    let clock = check_ring_merge_data(merge, ix.output_ring_data_hash)?;

    let merge_accounts = MergeRingAccounts::validate_and_parse(
        accounts,
        merge.nullifiers.len(),
        merge.cache_slot,
        ix.authority,
    )?;
    let (published_owner, output_view_tag) = match merge_accounts.owner {
        Some(owner) => {
            let owner_pk_hash = solana_owner_identity(owner.address().as_array())?;
            (owner_pk_hash, owner_pk_hash)
        }
        None => ([0u8; 32], first_nullifier(merge)?),
    };
    let owner_binding = MergeOwnerBinding::RingOwnerSigned {
        ring_program_id: hash_bytes(merge_accounts.ring_program_id.as_array())?,
        output_ring_data_hash: *ix.output_ring_data_hash,
        published_owner,
        output_encryption: merge.output_encryption,
    };
    finish_ring_merge(
        merge_accounts,
        merge,
        owner_binding,
        output_view_tag,
        &clock,
    )
}

fn check_ring_merge_data(
    merge: &MergeTransactIxDataRef<'_>,
    output_ring_data_hash: &[u8; 32],
) -> Result<Clock, pinocchio::error::ProgramError> {
    validate_field_elements(merge)?;
    check_field_element(
        output_ring_data_hash,
        "output ring data hash",
        None,
        ShieldedPoolError::NonCanonicalRingDataHash,
    )?;
    let clock = Clock::get()?;
    check_not_expired(merge.expiry_unix_ts, &clock)?;
    Ok(clock)
}

fn first_nullifier(merge: &MergeTransactIxDataRef<'_>) -> Result<[u8; 32], ShieldedPoolError> {
    merge
        .nullifiers
        .first()
        .copied()
        .ok_or(ShieldedPoolError::InvalidMergeShape)
}

fn finish_ring_merge(
    merge_accounts: MergeRingAccounts<'_>,
    merge: &MergeTransactIxDataRef<'_>,
    owner_binding: MergeOwnerBinding,
    output_view_tag: [u8; 32],
    clock: &Clock,
) -> ProgramResult {
    let cache = load_merge_cache(merge_accounts.cache, clock.unix_timestamp)?;
    // The indexer republishes the output `ring_data_hash` from the instruction
    // data as the output payload so the wallet can reconstruct the ring output.
    process_merge_core(
        MergeCoreAccounts {
            input_tree: merge_accounts.input_tree,
            output_tree: merge_accounts.output_tree,
            payer: merge_accounts.payer,
            nullifier_pdas: merge_accounts.nullifier_pdas,
        },
        merge,
        owner_binding,
        cache,
        output_view_tag,
        clock.slot,
    )
}
