use crate::instructions::shared::caused_by;
use arrayvec::ArrayVec;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError,
    event::InputTreeSequence,
    instruction::instruction_data::transact::{TransactIxDataRef, TreeContext},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    tree_slot::{pack_input_flags, TreeSlot},
    INPUT_TREES,
};
use zolana_tree::TreeAccount;

use super::{event::TreeWrite, verify::TransactProofInputs};
use crate::instructions::{nullifier_pda::InputTreeResult, shared::tree_error};

/// Resolve every declared input tree's roots into its proof tree slot, assign
/// the slots with the packed input flags, and insert each tree's nullifiers
/// into that tree's queue.
///
/// Inputs are grouped by tree, so each tree owns one contiguous run of inputs
/// and [`queue_nullifiers`] still sees consecutive queue numbers per tree. The
/// circuit applies its single dummy-input bit to every input slot whichever
/// tree it selected, so the published policy is the conjunction over all input
/// trees: anything weaker would relax the gate of the tightest tree.
#[profile]
pub(crate) fn apply_input_trees(
    input_tree_accounts: &mut [&mut AccountView],
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> Result<ArrayVec<InputTreeResult, INPUT_TREES>, ProgramError> {
    let shape = ShieldedPoolError::InvalidTransactShape;
    let mut results: ArrayVec<InputTreeResult, INPUT_TREES> = ArrayVec::new();
    let mut tree_slots: ArrayVec<TreeSlot, INPUT_TREES> = ArrayVec::new();
    let mut allow_dummy_inputs = true;

    let mut runs = input_runs(ix);
    for ((input_tree_account, context), run) in input_tree_accounts
        .iter_mut()
        .zip(&ix.tree_contexts)
        .zip(&mut runs)
    {
        let input_tree_address = input_tree_account.address().to_bytes();
        let mut input_tree = TreeAccount::from_account_view_mut(
            input_tree_account,
            &crate::ID,
            TREE_ACCOUNT_DISCRIMINATOR,
        )
        .map_err(tree_error)?;
        allow_dummy_inputs &= input_tree.allow_dummy_inputs().map_err(tree_error)?;
        tree_slots
            .try_push(resolve_input_tree_slot(&input_tree, context)?)
            .map_err(|_| shape)?;

        let first_input_queue_seq = queue_nullifiers(
            &mut input_tree,
            run.iter().map(|input| &input.nullifier_hash),
        )?;
        let forester_fee = input_tree
            .credit_insertion_fee(run.len() as u64)
            .map_err(tree_error)?;
        results
            .try_push(InputTreeResult {
                input_tree: InputTreeSequence {
                    tree: input_tree_address,
                    first_input_queue_seq,
                },
                forester_fee,
                fee_balance: input_tree.fee_balance(),
                tree_id: input_tree.tree_id(),
            })
            .map_err(|_| shape)?;
    }
    // Every declared context must have been paired with both a tree account
    // and an input run; a short or long run list means the instruction data and
    // the account list disagree.
    if runs.next().is_some()
        || results.len() != ix.tree_contexts.len()
        || results.len() != input_tree_accounts.len()
    {
        return Err(shape.into());
    }

    let input_flags = pack_input_flags(
        allow_dummy_inputs,
        ix.inputs.iter().map(|input| input.tree_index),
    )?;
    proof_inputs.assign_input_trees(tree_slots, input_flags);
    Ok(results)
}

/// The inputs of each declared tree, in context order: inputs are grouped by
/// `tree_index`, so every tree owns one contiguous run.
pub(crate) fn input_runs<'a>(
    ix: &'a TransactIxDataRef<'_>,
) -> impl Iterator<Item = &'a [zolana_interface::instruction::InputUtxo]> {
    ix.inputs
        .chunk_by(|left, right| left.tree_index == right.tree_index)
}

/// Insert every nullifier into `tree`'s queue and return the sequence number
/// of the first. The nullifier PDAs and the event derive input `i`'s number as
/// `first + i` within its tree's run, so a queue that hands out anything but
/// consecutive numbers is rejected rather than recorded wrongly.
pub(crate) fn queue_nullifiers<'n>(
    tree: &mut TreeAccount<'_>,
    nullifiers: impl Iterator<Item = &'n [u8; 32]>,
) -> Result<u64, ProgramError> {
    let mut first = None;
    for (position, nullifier) in (0u64..).zip(nullifiers) {
        let queue_index = tree
            .nullifier_tree()
            .insert_nullifier_into_queue(nullifier)
            .map_err(caused_by(ShieldedPoolError::NullifierTreeUpdateFailed))?;
        let expected = first
            .get_or_insert(queue_index)
            .checked_add(position)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if queue_index != expected {
            return Err(ShieldedPoolError::NullifierTreeUpdateFailed.into());
        }
    }
    first.ok_or(ShieldedPoolError::InvalidTransactShape.into())
}

/// One populated tree slot: the tree's id and the roots at its context's
/// root-index pair.
pub(crate) fn resolve_input_tree_slot(
    input_tree: &TreeAccount<'_>,
    context: &TreeContext,
) -> Result<TreeSlot, ProgramError> {
    Ok(TreeSlot {
        id: input_tree.tree_id_array(),
        utxo_root: input_tree
            .get_utxo_tree_root(context.utxo_tree_root_index)
            .map_err(tree_error)?,
        nullifier_root: input_tree
            .get_nullifier_tree_root(context.nullifier_tree_root_index)
            .map_err(tree_error)?,
    })
}

#[profile]
pub(crate) fn apply_output_tree(
    output_tree_account: &mut AccountView,
    ix: &TransactIxDataRef<'_>,
    slot: u64,
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
        .append_batch(ix.outputs.iter().map(|o| o.utxo_hash), slot)
        .map_err(tree_error)?;
    Ok(TreeWrite {
        first_output_leaf_index,
        output_tree: output_tree_address,
        output_tree_id: output_tree.tree_id(),
    })
}
