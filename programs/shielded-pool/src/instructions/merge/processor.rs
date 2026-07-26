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
            MergeExternalDataHash, MergeTransactIxDataRef, MERGE_INPUT_COUNT,
        },
        tag::MERGE_TRANSACT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::{TreeAccount, TreeError};

use super::{
    account::{load_user_record, MergeTransactAccounts},
    event::{build_merge_event, MergeTreeWrite},
    verify::{MergeOwnerBinding, MergeProof, MergeProofInputs},
};
use crate::instructions::{event::emit_general_event, shared::check_not_expired};

#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeTransactIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;

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
    // Owner-indexing view tag for the merged output: the owner signing pubkey (the
    // confidential default-zone tag, like every other confidential output). The
    // proof binds `signing_pk_field` to the same registered key, so a relayer cannot
    // alter it.
    let output_view_tag = pk_fields.signing_view_tag;

    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: MERGE_TRANSACT,
        expiry_unix_ts: ix.expiry_unix_ts,
        output_utxo_hash: ix.output_utxo_hash,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    // The `merge_view_tag` is single-use on both rails: inserting it into the
    // nullifier queue rejects a reused tag.
    process_merge_core(
        merge_accounts.tree,
        &ix,
        external_data_hash,
        MergeOwnerBinding::Registry { signing_pk_field },
        output_view_tag,
        Some(*ix.merge_view_tag),
        Vec::new(),
    )
}

/// Shared tail for `merge_transact` and `merge_zone`: read roots, nullify the
/// inputs, insert the single-use `merge_view_tag`, append the output, verify
/// the proof, and emit the event. The tree-derived dummy-input policy is
/// captured before any queue insertion or state append.
/// `output_data` is the event's output payload: empty for `merge_transact`, the
/// output `zone_data_hash` for `merge_zone`.
#[inline(never)]
pub(crate) fn process_merge_core(
    tree_account: &mut AccountView,
    ix: &MergeTransactIxDataRef<'_>,
    external_data_hash: [u8; 32],
    owner_binding: MergeOwnerBinding,
    output_view_tag: [u8; 32],
    single_use_tag: Option<[u8; 32]>,
    output_data: Vec<u8>,
) -> ProgramResult {
    let (tree_write, derived) = {
        let output_tree = tree_account.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            tree_account,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let mut derived = MergeProofInputs {
            utxo_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
            nullifier_tree_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
            external_data_hash,
            allow_dummy_inputs: bool_field(tree.allow_dummy_inputs().map_err(tree_error)?),
            owner_binding,
        };
        let tree_write = apply_tree(&mut tree, ix, output_tree, &mut derived, single_use_tag)?;
        (tree_write, derived)
    };

    let event = build_merge_event(ix, tree_write, output_view_tag, output_data);
    MergeProof::new(ix, derived).verify()?;
    emit_general_event(EventKind::Merge, event)
}

#[inline(never)]
fn apply_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
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
        tree.nullifer_tree()
            .insert_address_into_queue(nullifier)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        inputs.push(Input {
            tree: output_tree,
            input_queue_seq: nullifier_seq_base + i as u64,
            nullifier: *nullifier,
        });
    }

    // The `merge_view_tag` is single-use on both rails; insert it into the
    // nullifier queue so a duplicate tag is rejected (replay protection).
    if let Some(tag) = single_use_tag {
        tree.nullifer_tree()
            .insert_address_into_queue(&tag)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
    }

    let output_leaf_index = tree.utxo_tree().next_index();
    tree.utxo_tree()
        .append(*ix.output_utxo_hash)
        .map_err(tree_error)?;

    Ok(MergeTreeWrite {
        inputs,
        output_leaf_index,
        output_tree,
    })
}

fn bool_field(value: bool) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[31] = u8::from(value);
    field
}

fn tree_error(e: TreeError) -> ProgramError {
    match e {
        TreeError::Paused => ShieldedPoolError::TreePaused.into(),
        TreeError::InvalidRootIndex => ShieldedPoolError::StaleNullifierRoot.into(),
        TreeError::TreeIsFull => ShieldedPoolError::StateAppendFailed.into(),
        _ => ShieldedPoolError::InvalidTreeAccounts.into(),
    }
}
