use light_program_profiler::profile;
use pinocchio::error::ProgramError;
use zolana_interface::{
    error::ShieldedPoolError, event::Input,
    instruction::instruction_data::transact::TransactIxDataRef,
};
use zolana_tree::TreeAccount;

use super::{event::TreeWrite, verify::TransactProofInputs};
use crate::instructions::shared::{bool_field, tree_error};

#[profile]
pub(crate) fn apply_input_tree(
    input_tree: &mut TreeAccount<'_>,
    ix: &TransactIxDataRef<'_>,
    input_tree_address: [u8; 32],
    proof_inputs: &mut TransactProofInputs,
) -> Result<Vec<Input>, ProgramError> {
    let error = ShieldedPoolError::InvalidTransactShape;
    proof_inputs.allow_dummy_inputs =
        bool_field(input_tree.allow_dummy_inputs().map_err(tree_error)?);
    let mut inputs = Vec::with_capacity(ix.inputs.len());
    let nullifier_seq_base = input_tree.nullifer_tree().queue_batches.next_index;
    for (i, input) in ix.inputs.iter().enumerate() {
        *proof_inputs.utxo_roots.get_mut(i).ok_or(error)? = input_tree
            .get_utxo_tree_root(input.utxo_tree_root_index)
            .map_err(tree_error)?;
        *proof_inputs.nullifier_tree_roots.get_mut(i).ok_or(error)? = input_tree
            .get_nullifier_tree_root(input.nullifier_tree_root_index)
            .map_err(tree_error)?;
        input_tree
            .nullifer_tree()
            .insert_address_into_queue(&input.nullifier_hash)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        inputs.push(Input {
            tree: input_tree_address,
            input_queue_seq: nullifier_seq_base + i as u64,
            nullifier: input.nullifier_hash,
        });
    }

    Ok(inputs)
}

#[profile]
pub(crate) fn apply_output_tree(
    output_tree: &mut TreeAccount<'_>,
    ix: &TransactIxDataRef<'_>,
    output_tree_address: [u8; 32],
    inputs: Vec<Input>,
) -> Result<TreeWrite, ProgramError> {
    // Leaf index the first output lands at; the rest follow sequentially.
    let first_output_leaf_index = output_tree.utxo_tree().next_index();
    output_tree
        .utxo_tree()
        .append_batch(ix.outputs.iter().map(|o| o.utxo_hash))
        .map_err(tree_error)?;
    Ok(TreeWrite {
        inputs,
        first_output_leaf_index,
        output_tree: output_tree_address,
    })
}
