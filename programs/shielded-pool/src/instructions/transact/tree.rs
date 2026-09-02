use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError, event::Input,
    instruction::instruction_data::transact::TransactIxDataRef,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
};
use zolana_tree::TreeAccount;

use super::{
    event::TreeWrite,
    verify::{TransactProofInputs, MAX_INPUTS},
};
use crate::instructions::shared::{bool_field, tree_error};

pub(crate) struct InputTreeResult {
    pub inputs: Vec<Input>,
    pub zkp_batch_size: u64,
    pub tree_id: u16,
}

#[profile]
pub(crate) fn apply_input_tree(
    input_tree_account: &mut AccountView,
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> Result<InputTreeResult, ProgramError> {
    let error = ShieldedPoolError::InvalidTransactShape;
    let input_tree_address = input_tree_account.address().to_bytes();
    let mut input_tree = TreeAccount::from_account_view_mut(
        input_tree_account,
        &crate::ID,
        TREE_ACCOUNT_DISCRIMINATOR,
    )
    .map_err(tree_error)?;
    let allow_dummy_inputs = bool_field(input_tree.allow_dummy_inputs().map_err(tree_error)?);
    let mut inputs = Vec::with_capacity(ix.inputs.len());
    let mut utxo_roots = [[0u8; 32]; MAX_INPUTS];
    let mut nullifier_tree_roots = [[0u8; 32]; MAX_INPUTS];
    for (i, input) in ix.inputs.iter().enumerate() {
        // 1. Assign state tree root to proof inputs.
        *utxo_roots.get_mut(i).ok_or(error)? = input_tree
            .get_utxo_tree_root(input.utxo_tree_root_index)
            .map_err(tree_error)?;
        // 2. Assign nullifier tree root to proof inputs.
        *nullifier_tree_roots.get_mut(i).ok_or(error)? = input_tree
            .get_nullifier_tree_root(input.nullifier_tree_root_index)
            .map_err(tree_error)?;
        // 3. insert_nullifier_into_queue
        let queue_index = input_tree
            .nullifier_tree()
            .insert_nullifier_into_queue(&input.nullifier_hash)
            .map_err(|_| ShieldedPoolError::NullifierTreeUpdateFailed)?;
        // 4. Build indexer nullifier queue data.
        inputs.push(Input {
            tree: input_tree_address,
            input_queue_seq: queue_index,
            nullifier: input.nullifier_hash,
        });
    }
    proof_inputs.assign_input_tree(
        &utxo_roots[..ix.inputs.len()],
        &nullifier_tree_roots[..ix.inputs.len()],
        allow_dummy_inputs,
    )?;
    let zkp_batch_size = input_tree.nullifier_tree().zkp_batch_size;

    Ok(InputTreeResult {
        inputs,
        zkp_batch_size,
        tree_id: input_tree.tree_id(),
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
    })
}
