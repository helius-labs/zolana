use crate::instructions::shared::caused_by;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError,
    event::Input,
    instruction::instruction_data::transact::{InputUtxo, TransactIxDataRef},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    tree_slot::TreeSlot,
};
use zolana_tree::TreeAccount;

use super::{event::TreeWrite, verify::TransactProofInputs};
use crate::instructions::{
    nullifier_pda::InputTreeResult,
    shared::{bool_field, tree_error},
};

/// Resolve `input_tree`'s roots into the proof's tree slot, assign them with
/// the tree's dummy-input policy, and insert every nullifier into the tree's
/// queue.
///
/// The circuit publishes `INPUT_TREES` slots, but SPP spends from one
/// `input_tree`, so every input must reference the same pair of root indexes:
/// the roots they resolve to fill slot 0 and the remaining slots stay zero.
#[profile]
pub(crate) fn apply_input_tree(
    input_tree_account: &mut AccountView,
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> Result<InputTreeResult, ProgramError> {
    let input_tree_address = input_tree_account.address().to_bytes();
    let mut input_tree = TreeAccount::from_account_view_mut(
        input_tree_account,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(tree_error)?;
    let allow_dummy_inputs = bool_field(input_tree.allow_dummy_inputs().map_err(tree_error)?);
    let tree_slot = resolve_input_tree_slot(&input_tree, &ix.inputs)?;
    proof_inputs.assign_input_tree(tree_slot, allow_dummy_inputs);

    let mut inputs = Vec::with_capacity(ix.inputs.len());
    for input in &ix.inputs {
        let queue_index = input_tree
            .nullifier_tree()
            .insert_nullifier_into_queue(&input.nullifier_hash)
            .map_err(caused_by(ShieldedPoolError::NullifierTreeUpdateFailed))?;
        inputs.push(Input {
            tree: input_tree_address,
            input_queue_seq: queue_index,
            nullifier: input.nullifier_hash,
        });
    }
    let forester_fee = input_tree
        .credit_insertion_fee(ix.inputs.len() as u64)
        .map_err(tree_error)?;

    Ok(InputTreeResult {
        inputs,
        forester_fee,
        fee_balance: input_tree.fee_balance(),
        tree_id: input_tree.tree_id(),
    })
}

/// The one populated tree slot of a spend: `input_tree`'s id and the roots at
/// the indexes every input references. An input whose indexes differ from
/// input 0's is `InputTreeRootIndexMismatch`.
pub(crate) fn resolve_input_tree_slot(
    input_tree: &TreeAccount<'_>,
    inputs: &[InputUtxo],
) -> Result<TreeSlot, ProgramError> {
    let first = inputs
        .first()
        .ok_or(ShieldedPoolError::InvalidTransactShape)?;
    if inputs.iter().any(|input| {
        input.utxo_tree_root_index != first.utxo_tree_root_index
            || input.nullifier_tree_root_index != first.nullifier_tree_root_index
    }) {
        return Err(ShieldedPoolError::InputTreeRootIndexMismatch.into());
    }
    Ok(TreeSlot {
        id: input_tree.tree_id_array(),
        utxo_root: input_tree
            .get_utxo_tree_root(first.utxo_tree_root_index)
            .map_err(tree_error)?,
        nullifier_root: input_tree
            .get_nullifier_tree_root(first.nullifier_tree_root_index)
            .map_err(tree_error)?,
    })
}

#[profile]
pub(crate) fn apply_output_tree(
    output_tree_account: &mut AccountView,
    ix: &TransactIxDataRef<'_>,
    inputs: Vec<Input>,
) -> Result<TreeWrite, ProgramError> {
    let output_tree_address = output_tree_account.address().to_bytes();
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
        .append_batch(ix.outputs.iter().map(|o| o.utxo_hash))
        .map_err(tree_error)?;
    Ok(TreeWrite {
        inputs,
        first_output_leaf_index,
        output_tree: output_tree_address,
        output_tree_id: output_tree.tree_id(),
    })
}
