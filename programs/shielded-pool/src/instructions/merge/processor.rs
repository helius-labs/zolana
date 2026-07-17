use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{EventKind, Input},
    instruction::{
        instruction_data::merge_transact::{
            MergeExternalDataHash, MergeTransactIxDataRef, MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
            MERGE_INPUT_COUNT,
        },
        tag::MERGE_TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::{TreeAccount, TreeError};

use super::{
    account::{load_user_record, MergeTransactAccounts},
    event::{build_merge_event, MergeTreeWrite},
    verify::{pk_field, MergeOwnerBinding, MergeProof, MergeProofInputs},
};
use crate::instructions::{
    event::emit_general_event,
    shared::{check_not_expired, reject_reserved_nullifier},
};

#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeTransactIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;

    if ix.encrypted_utxo.first() != Some(&MERGE_ENCRYPTED_UTXO_TYPE_PREFIX) {
        return Err(ShieldedPoolError::InvalidMergeOutputScheme.into());
    }

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeTransactAccounts::validate_and_parse(&crate::ID, accounts)?;

    let pk_fields = load_user_record(merge_accounts.user_record, ix.eddsa_owner)?;

    // Per-user merge opt-in: the owner must have enabled merging. Any caller may
    // then run the merge.
    if !pk_fields.merging_enabled {
        return Err(ShieldedPoolError::MergeDisabled.into());
    }

    let signing_pk_field = pk_fields.signing_pk_field;
    let viewing_pk_field = pk_field(&pk_fields.viewing)?;
    // Owner-indexing view tag for the merged output: the owner signing pubkey (the
    // confidential default-zone tag, like every other confidential output). The
    // proof binds `signing_pk_field` to the same registered key, so a relayer cannot
    // alter it.
    let output_view_tag = pk_fields.signing_view_tag;

    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: MERGE_TRANSACT,
        expiry_unix_ts: ix.expiry_unix_ts,
        output_utxo_hash: ix.output_utxo_hash,
        encrypted_utxo: ix.encrypted_utxo,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let derived = MergeProofInputs {
        utxo_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
        nullifier_tree_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
        external_data_hash,
        owner_binding: MergeOwnerBinding::Registry {
            signing_pk_field,
            viewing_pk_field,
        },
    };

    process_merge_core(
        merge_accounts.tree,
        &ix,
        derived,
        output_view_tag,
        clock.slot,
        None,
    )
}

/// Shared tail for `merge_transact` and `merge_zone`: read roots, nullify the
/// inputs (and, for `merge_zone`, insert the single-use `merge_view_tag`), append
/// the output, verify the proof, and emit the event. `derived` already carries
/// the resolved `external_data_hash` and the variant-specific owner binding,
/// which selects both the public-input shape and the verifying key.
#[inline(never)]
pub(crate) fn process_merge_core(
    tree_account: &mut AccountView,
    ix: &MergeTransactIxDataRef<'_>,
    mut derived: MergeProofInputs,
    output_view_tag: [u8; 32],
    current_slot: u64,
    single_use_tag: Option<[u8; 32]>,
) -> ProgramResult {
    let tree_write = {
        let output_tree = tree_account.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            tree_account,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        apply_tree(
            &mut tree,
            ix,
            current_slot,
            output_tree,
            &mut derived,
            single_use_tag,
        )?
    };

    let event = build_merge_event(ix, tree_write, output_view_tag);
    MergeProof::new(ix, derived).verify()?;
    emit_general_event(EventKind::Merge, event)
}

#[inline(never)]
fn apply_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    current_slot: u64,
    output_tree: [u8; 32],
    derived: &mut MergeProofInputs,
    single_use_tag: Option<[u8; 32]>,
) -> Result<MergeTreeWrite, ProgramError> {
    let shape = ShieldedPoolError::InvalidMergeShape;
    let nullifier_seq_base = tree.nullifer_tree().queue_batches.next_index;
    let mut inputs = Vec::with_capacity(MERGE_INPUT_COUNT);
    for i in 0..MERGE_INPUT_COUNT {
        let nullifier = ix.nullifiers.get(i).ok_or(shape)?;
        let utxo_root_index = *ix.utxo_tree_root_index.get(i).ok_or(shape)?;
        let nullifier_root_index = *ix.nullifier_tree_root_index.get(i).ok_or(shape)?;

        *derived.utxo_roots.get_mut(i).ok_or(shape)? = tree
            .get_utxo_tree_root(utxo_root_index)
            .map_err(tree_error)?;
        *derived.nullifier_tree_roots.get_mut(i).ok_or(shape)? = tree
            .get_nullifier_tree_root(nullifier_root_index)
            .map_err(tree_error)?;
        reject_reserved_nullifier(nullifier)?;
        tree.nullifer_tree()
            .insert_address_into_queue(nullifier, &current_slot)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        inputs.push(Input {
            tree: output_tree,
            input_queue_seq: nullifier_seq_base + i as u64,
            nullifier: *nullifier,
        });
    }

    // `merge_zone` indexes the output by a single-use `merge_view_tag`; insert it
    // into the nullifier queue so a duplicate tag is rejected (replay protection).
    if let Some(tag) = single_use_tag {
        tree.nullifer_tree()
            .insert_address_into_queue(&tag, &current_slot)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
    }

    let output_leaf_index = tree.utxo_tree().next_index();
    tree.utxo_tree().append(*ix.output_utxo_hash);

    Ok(MergeTreeWrite {
        inputs,
        output_leaf_index,
        output_tree,
    })
}

fn tree_error(e: TreeError) -> ProgramError {
    match e {
        TreeError::Paused => ShieldedPoolError::TreePaused.into(),
        TreeError::InvalidRootIndex => ShieldedPoolError::StaleNullifierRoot.into(),
        _ => ShieldedPoolError::InvalidTreeAccounts.into(),
    }
}
