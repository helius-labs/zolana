use crate::instructions::shared::caused_by;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView};
use zolana_hasher::hash_chain::HashChain;
use zolana_interface::{
    error::ShieldedPoolError, instruction::instruction_data::transact::TransactIxDataRef,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use super::{event::TreeWrite, verify::TransactProofInputs};
use crate::instructions::{
    nullifier_pda::InputTreeResult,
    shared::{bool_field, tree_error},
};

#[profile]
pub(crate) fn apply_input_tree(
    input_tree_account: &mut AccountView,
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> Result<InputTreeResult, ProgramError> {
    let mut input_tree = TreeAccount::from_account_view_mut(
        input_tree_account,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(tree_error)?;
    let allow_dummy_inputs = bool_field(input_tree.allow_dummy_inputs().map_err(tree_error)?);
    // Folded in place: holding the roots in count-sized arrays and copying them
    // into identically shaped arrays in `TransactProofInputs` was two frames of
    // buffer that grew with the input count.
    let mut first_input_queue_seq: Option<u64> = None;
    let mut utxo_root_chain = HashChain::new();
    let mut nullifier_tree_root_chain = HashChain::new();
    for input in ix.tail.inputs.iter() {
        // 1. Fold the state tree root into the proof input chain.
        utxo_root_chain.push(
            &input_tree
                .get_utxo_tree_root(input.utxo_tree_root_index)
                .map_err(tree_error)?,
        )?;
        // 2. Fold the nullifier tree root into the proof input chain.
        nullifier_tree_root_chain.push(
            &input_tree
                .get_nullifier_tree_root(input.nullifier_tree_root_index)
                .map_err(tree_error)?,
        )?;
        // 3. insert_nullifier_into_queue
        // 3. Queue the nullifier, keeping only the first index: the queue
        //    counter is monotone and this loop walks one tree in order, so every
        //    later index is `first + i`.
        let queue_index = input_tree
            .nullifier_tree()
            .insert_nullifier_into_queue(&input.nullifier_hash)
            .map_err(caused_by(ShieldedPoolError::NullifierTreeUpdateFailed))?;
        if first_input_queue_seq.is_none() {
            first_input_queue_seq = Some(queue_index);
        }
    }
    proof_inputs.assign_input_tree(
        utxo_root_chain.finish(),
        nullifier_tree_root_chain.finish(),
        ix.tail.inputs.len(),
        allow_dummy_inputs,
    )?;
    let forester_fee = input_tree
        .credit_insertion_fee(ix.tail.inputs.len() as u64)
        .map_err(tree_error)?;

    Ok(InputTreeResult {
        first_input_queue_seq: first_input_queue_seq.unwrap_or_default(),
        input_count: ix.tail.inputs.len(),
        forester_fee,
        fee_balance: input_tree.fee_balance(),
        tree_id: input_tree.tree_id(),
    })
}

#[profile]
pub(crate) fn apply_output_tree(
    output_tree_account: &mut AccountView,
    ix: &TransactIxDataRef<'_>,
) -> Result<TreeWrite, ProgramError> {
    let mut output_tree = TreeAccount::from_account_view_mut(
        output_tree_account,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(tree_error)?;
    // Leaf index the first output lands at; the rest follow sequentially.
    let first_output_leaf_index = output_tree.utxo_tree().next_index();
    output_tree
        .utxo_tree()
        .append_batch(ix.bound.outputs.iter().map(|o| o.utxo_hash))
        .map_err(tree_error)?;
    Ok(TreeWrite {
        first_output_leaf_index,
    })
}
