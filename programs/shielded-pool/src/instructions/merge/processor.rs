use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{EventKind, Input},
    instruction::instruction_data::merge_transact::{
        MergeExternalDataHash, MergeTransactIxDataRef, MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
        MERGE_INPUT_COUNT,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::{TreeAccount, TreeError};

use super::{
    account::{load_user_record, MergeTransactAccounts},
    event::{build_merge_event, MergeTreeWrite},
    verify::{pk_field, MergeProof, MergeProofInputs},
};
use crate::instructions::event::emit_general_event;

#[inline(never)]
pub fn process_merge_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeTransactIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;

    if ix.encrypted_utxo.first() != Some(&MERGE_ENCRYPTED_UTXO_TYPE_PREFIX) {
        return Err(ShieldedPoolError::InvalidMergeOutputScheme.into());
    }

    let clock = Clock::get()?;
    if clock.unix_timestamp < 0 || (clock.unix_timestamp as u64) > ix.expiry_unix_ts {
        return Err(ShieldedPoolError::ExpiredTransaction.into());
    }

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
        expiry_unix_ts: ix.expiry_unix_ts,
        output_utxo_hash: ix.output_utxo_hash,
        encrypted_utxo: ix.encrypted_utxo,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let mut derived = MergeProofInputs {
        utxo_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
        nullifier_tree_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
        external_data_hash,
        signing_pk_field,
        viewing_pk_field,
    };

    let tree_write = {
        let output_tree = merge_accounts.tree.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            merge_accounts.tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        apply_tree(&mut tree, &ix, clock.slot, output_tree, &mut derived)?
    };

    let event = build_merge_event(&ix, tree_write, output_view_tag);
    MergeProof::new(&ix, derived).verify()?;
    emit_general_event(EventKind::Merge, event)
}

#[inline(never)]
fn apply_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeTransactIxDataRef<'_>,
    current_slot: u64,
    output_tree: [u8; 32],
    derived: &mut MergeProofInputs,
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
            .insert_address_into_queue(nullifier, &current_slot)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        inputs.push(Input {
            tree: output_tree,
            input_queue_seq: nullifier_seq_base + i as u64,
            nullifier: *nullifier,
        });
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
