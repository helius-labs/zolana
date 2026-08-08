use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{EventKind, Input},
    instruction::{
        instruction_data::merge_chain_transact::MergeChainTransactIxDataRef,
        tag::MERGE_CHAIN_TRANSACT, MergeExternalDataHash,
    },
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use super::verify::{MergeChainProof, MergeChainProofInputs};
use crate::instructions::{
    event::emit_general_event,
    merge::{
        account::{load_user_record, MergeTransactAccounts},
        event::build_merge_event,
        processor::apply_output_tree,
    },
    shared::{bool_field, check_not_expired, collect_forester_fee, tree_error},
};

/// Settle a tree of merge legs against one recursive proof.
///
/// Only the top leg's output is appended, and every intermediate output stays
/// inside the proof. Only the nullifiers of the UTXOs the chain spent out of
/// the state tree reach the chain, so the transaction size caps the run rather
/// than the merge circuit's eight inputs.
#[inline(never)]
pub fn process_merge_chain_transact_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeChainTransactIxDataRef::from_bytes(data)
        .map_err(|_| ShieldedPoolError::InvalidMergeShape)?;

    let clock = Clock::get()?;
    check_not_expired(ix.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeTransactAccounts::validate_and_parse(accounts)?;
    let pk_fields = load_user_record(merge_accounts.user_record, ix.eddsa_owner)?;
    if !pk_fields.merging_enabled {
        return Err(ShieldedPoolError::MergeDisabled.into());
    }

    // Domain-separated by this instruction's tag, so a chain proof cannot be
    // replayed as a plain merge and the reverse.
    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: MERGE_CHAIN_TRANSACT,
        expiry_unix_ts: ix.expiry_unix_ts,
        output_utxo_hash: ix.output_utxo_hash,
    }
    .hash()
    .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed)?;

    let (inputs, derived, zkp_batch_size) = {
        let input_tree = merge_accounts.input_tree.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *merge_accounts.input_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        let allow_dummy_inputs = tree.allow_dummy_inputs().map_err(tree_error)?;
        let mut derived = MergeChainProofInputs {
            utxo_roots: Vec::with_capacity(ix.nullifiers.len()),
            nullifier_tree_roots: Vec::with_capacity(ix.nullifiers.len()),
            external_data_hash,
            allow_dummy_inputs: bool_field(allow_dummy_inputs),
            signing_pk_field: pk_fields.signing_pk_field,
        };
        let inputs = apply_input_tree(&mut tree, &ix, input_tree, &mut derived)?;
        let zkp_batch_size = tree.nullifer_tree().queue_batches.zkp_batch_size;
        (inputs, derived, zkp_batch_size)
    };

    let tree_write = {
        let output_tree = merge_accounts.output_tree.address().to_bytes();
        let mut tree = TreeAccount::from_account_view_mut(
            &mut *merge_accounts.output_tree,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        apply_output_tree(&mut tree, ix.output_utxo_hash, output_tree, inputs)?
    };

    let spent = ix.nullifiers.len() as u64;
    // The level shape is what tells a wallet where each leg's nullifiers start.
    // Every leg derives its dummy nullifiers from its own first nullifier, and
    // the settled output's blinding comes from the top leg's, so without the
    // shape a reader cannot reconstruct the output it just paid for.
    let event = build_merge_event(
        *ix.output_utxo_hash,
        tree_write,
        pk_fields.signing_view_tag,
        ix.levels.clone(),
    );
    #[cfg(feature = "vk-registry")]
    MergeChainProof::new(&ix, derived).verify_registered(merge_accounts.vk_registry())?;
    #[cfg(not(feature = "vk-registry"))]
    MergeChainProof::new(&ix, derived).verify()?;
    collect_forester_fee(
        merge_accounts.payer,
        merge_accounts.input_tree,
        spent,
        zkp_batch_size,
    )?;
    emit_general_event(EventKind::Merge, event)
}

#[inline(never)]
fn apply_input_tree(
    tree: &mut TreeAccount<'_>,
    ix: &MergeChainTransactIxDataRef<'_>,
    input_tree: [u8; 32],
    derived: &mut MergeChainProofInputs,
) -> Result<Vec<Input>, ProgramError> {
    let shape = ShieldedPoolError::InvalidMergeShape;
    let nullifier_seq_base = tree.nullifer_tree().queue_batches.next_index;
    let mut inputs = Vec::with_capacity(ix.nullifiers.len());
    for (i, nullifier) in ix.nullifiers.iter().enumerate() {
        let utxo_root_index = *ix.utxo_tree_root_index.get(i).ok_or(shape)?;
        let nullifier_root_index = *ix.nullifier_tree_root_index.get(i).ok_or(shape)?;

        derived.utxo_roots.push(
            tree.get_utxo_tree_root(utxo_root_index)
                .map_err(tree_error)?,
        );
        derived.nullifier_tree_roots.push(
            tree.get_nullifier_tree_root(nullifier_root_index)
                .map_err(tree_error)?,
        );
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
