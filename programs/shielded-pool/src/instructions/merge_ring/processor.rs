use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{merge_ring::MergeRingIxDataRef, merge_transact::MergeExternalDataHash},
        tag::RING_MERGE_TRANSACT,
    },
};

use super::account::MergeRingAccounts;
use crate::instructions::{
    merge::{
        processor::{MergeCore, MergeCoreAccounts},
        verify::MergeOwnerBinding,
    },
    shared::check_not_expired,
};

/// Policy-ring analog of `merge_transact`, invoked via CPI from a ring program.
/// The ring's `ring_config` account signs (authorization), the merged output is
/// indexed by the first input nullifier, and SPP does not check
/// `protocol_config.merge_authorities`.
#[inline(never)]
pub fn process_merge_ring_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix =
        MergeRingIxDataRef::from_bytes(data).map_err(|_| ShieldedPoolError::InvalidMergeShape)?;
    let merge = &ix.merge;
    let clock = Clock::get()?;
    check_not_expired(merge.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeRingAccounts::validate_and_parse(accounts)?;

    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: RING_MERGE_TRANSACT,
        expiry_unix_ts: merge.expiry_unix_ts,
        output_utxo_hash: merge.output_utxo_hash,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    // The proof binds `ring_program_id` from the signing `ring_config` and the
    // output `ring_data_hash` the ring program selected. A policy ring has no
    // `user_record` registry, so the `Ring` binding omits owner identity (see
    // `MergeProof::public_input_hash`).
    let ring_program_id = hash_bytes(merge_accounts.ring_program_id.as_array())?;
    let owner_binding = MergeOwnerBinding::Ring {
        ring_program_id,
        output_ring_data_hash: *ix.output_ring_data_hash,
    };

    let vk_registry = merge_accounts.vk_registry();
    MergeCore {
        ix: merge,
        external_data_hash,
        owner_binding,
        output_view_tag: *merge
            .nullifiers
            .first()
            .ok_or(ShieldedPoolError::InvalidMergeShape)?,
        output_data: ix.output_ring_data_hash.to_vec(),
    }
    .process(MergeCoreAccounts {
        input_tree: merge_accounts.input_tree,
        output_tree: merge_accounts.output_tree,
        payer: merge_accounts.payer,
        vk_registry,
    })
}
