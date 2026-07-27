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
use zolana_tree::TreeAccount;

use super::{
    account::{load_user_record, MergeTransactAccounts},
    event::{build_merge_event, MergeTreeWrite},
    verify::{MergeOwnerBinding, MergeProof, MergeProofInputs},
};
use crate::instructions::{
    event::emit_general_event,
    shared::{bool_field, check_not_expired, collect_forester_fee, tree_error},
};

#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeTransactIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeTransactAccounts::validate_and_parse(accounts)?;

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

    process_merge_core(
        merge_accounts.input_tree,
        merge_accounts.output_tree,
        merge_accounts.payer,
        &ix,
        external_data_hash,
        MergeOwnerBinding::Registry { signing_pk_field },
        output_view_tag,
        Vec::new(),
    )
}

/// Shared tail for `merge_transact` and `merge_zone`: read roots, nullify the
/// inputs, append the output, verify the proof, and emit the event. The
/// tree-derived dummy-input policy is
/// captured before any queue insertion or state append.
/// `output_data` is the event's output payload: empty for `merge_transact`, the
/// output `zone_data_hash` for `merge_zone`.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_merge_core(
    input_tree_account: &mut AccountView,
    output_tree_account: &mut AccountView,
    payer: &AccountView,
    ix: &MergeTransactIxDataRef<'_>,
    external_data_hash: [u8; 32],
    owner_binding: MergeOwnerBinding,
    output_view_tag: [u8; 32],
    output_data: Vec<u8>,
) -> ProgramResult {
    let (inputs, derived, zkp_batch_size) = {
        let input_tree = input_tree_account.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *input_tree_account,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let allow_dummy_inputs = tree.allow_dummy_inputs().map_err(tree_error)?;
        // Merge proofs are currently built with `allow_dummy_inputs = true`.
        // Keep the explicit capacity error instead of letting proof verification
        // fail opaquely when the tree disables dummy inputs.
        if !allow_dummy_inputs {
            return Err(ShieldedPoolError::NullifierTreeTooFullForMerge.into());
        }
        let mut derived = MergeProofInputs {
            utxo_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
            nullifier_tree_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
            external_data_hash,
            allow_dummy_inputs: bool_field(allow_dummy_inputs),
            owner_binding,
        };
        let inputs = apply_input_tree(&mut tree, ix, input_tree, &mut derived)?;
        let zkp_batch_size = tree.nullifer_tree().queue_batches.zkp_batch_size;
        (inputs, derived, zkp_batch_size)
    };
    let tree_write = {
        let output_tree = output_tree_account.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *output_tree_account,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        apply_output_tree(&mut tree, ix, output_tree, inputs)?
    };

    let event = build_merge_event(ix, tree_write, output_view_tag, output_data);
    MergeProof::new(ix, derived).verify()?;
    collect_forester_fee(
        payer,
        input_tree_account,
        MERGE_INPUT_COUNT as u64,
        zkp_batch_size,
    )?;
    emit_general_event(EventKind::Merge, event)
}

#[inline(never)]
fn apply_input_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    input_tree: [u8; 32],
    derived: &mut MergeProofInputs,
) -> Result<Vec<Input>, ProgramError> {
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
            .insert_nullifier_into_queue(nullifier)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        inputs.push(Input {
            tree: input_tree,
            input_queue_seq: nullifier_seq_base + i as u64,
            nullifier: *nullifier,
        });
    }

    Ok(inputs)
}

fn apply_output_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    output_tree: [u8; 32],
    inputs: Vec<Input>,
) -> Result<MergeTreeWrite, ProgramError> {
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
