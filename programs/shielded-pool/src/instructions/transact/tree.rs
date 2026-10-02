use crate::instructions::shared::caused_by;
use arrayvec::ArrayVec;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError,
    event::InputTreeSequence,
    instruction::instruction_data::transact::{TransactIxDataRef, TreeContext, NO_UTXO_ROOT},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    tree_slot::{pack_input_flags, resolve_tree_slot, TreeSlot},
    INPUT_TREES, MAX_INPUT_TREES,
};
use zolana_tree::TreeAccount;

use super::{account::TransactAccounts, event::TreeWrite, verify::TransactProofInputs};
use crate::instructions::{
    nullifier_pda::{create_nullifier_pdas, InputTreeResult},
    shared::tree_error,
};

/// Resolve every declared input tree's roots into its proof tree slot, assign
/// the slots with the packed input flags, queue each tree's nullifiers and
/// create their PDAs. Retain only the queue metadata needed by the event.
///
/// Steps 1-5 complete each tree before moving to the next:
/// 1. Select the inputs that reference the tree, in input order.
/// 2. Load the tree, combine its dummy-input policy and resolve its roots.
/// 3. Queue its nullifiers and credit its insertion fee.
/// 4. Release the tree-data borrow, collect the fee and create its PDAs.
/// 5. Retain its first queue sequence for the event.
/// 6. Assign the tree slots and packed input flags to the proof inputs.
///
/// `tree_input_counts` is the result of `validate_input_tree_contexts`: every
/// declared tree has at least one input and the counts cover every input.
///
/// Inputs may reference their trees in any order. Each tree queues the inputs
/// that reference it in input order, so the tree library assigns them
/// consecutive queue numbers in that order. The circuit applies its single
/// dummy-input bit to every input slot whichever tree it selected, so the
/// published policy is the conjunction over all input trees: anything weaker
/// would relax the gate of the tightest tree.
#[profile]
pub(crate) fn apply_input_trees(
    accounts: &mut TransactAccounts<'_>,
    ix: &TransactIxDataRef<'_>,
    tree_input_counts: [usize; MAX_INPUT_TREES],
    proof_inputs: &mut TransactProofInputs,
) -> Result<ArrayVec<InputTreeSequence, INPUT_TREES>, ProgramError> {
    let TransactAccounts {
        payer,
        input_trees,
        nullifier_pdas,
        ..
    } = accounts;
    let shape = ShieldedPoolError::InvalidTransactShape;
    let mut sequences: ArrayVec<InputTreeSequence, INPUT_TREES> = ArrayVec::new();
    let mut tree_slots: ArrayVec<TreeSlot, INPUT_TREES> = ArrayVec::new();
    let mut allow_dummy_inputs = true;
    if nullifier_pdas.len() != ix.inputs.len() {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }
    // Every declared context needs its tree account and its input count, so
    // the zip below visits every declared tree.
    if input_trees.len() != ix.tree_contexts.len() || ix.tree_contexts.len() > MAX_INPUT_TREES {
        return Err(shape.into());
    }

    for (tree_index, ((input_tree_account, context), tree_input_count)) in (0u8..).zip(
        input_trees
            .iter_mut()
            .zip(&ix.tree_contexts)
            .zip(tree_input_counts),
    ) {
        // 1. Select the inputs that reference this tree, in input order.
        let tree_inputs = || {
            ix.inputs
                .iter()
                .filter(move |input| input.tree_index == tree_index)
        };
        let input_tree_address = input_tree_account.address().to_bytes();
        let result = {
            // 2. Load the tree, combine its dummy-input policy and resolve its roots.
            let mut input_tree = TreeAccount::from_account_view_mut(
                input_tree_account,
                &crate::ID,
                TREE_ACCOUNT_DISCRIMINATOR,
            )
            .map_err(tree_error)?;
            allow_dummy_inputs &=
                input_tree.dummy_input_headroom().map_err(tree_error)? >= tree_input_count as u64;
            tree_slots
                .try_push(resolve_input_tree_slot(&input_tree, context)?)
                .map_err(|_| shape)?;

            // 3. Queue its nullifiers and credit its insertion fee.
            let first_input_queue_seq = input_tree.nullifier_tree().queue_next_index;
            for input in tree_inputs() {
                input_tree
                    .nullifier_tree()
                    .insert_nullifier_into_queue(&input.nullifier_hash)
                    .map_err(caused_by(ShieldedPoolError::NullifierTreeUpdateFailed))?;
            }
            let forester_fee = input_tree
                .credit_insertion_fee(tree_input_count as u64)
                .map_err(tree_error)?;
            InputTreeResult {
                input_tree: InputTreeSequence {
                    tree: input_tree_address,
                    first_input_queue_seq,
                },
                forester_fee,
                fee_balance: input_tree.fee_balance(),
                tree_id: input_tree.tree_id(),
            }
        };
        // 4. Release the tree-data borrow before the CPIs. The helper collects
        // this tree's fee before debiting it for any PDA rent.
        create_nullifier_pdas(
            payer,
            input_tree_account,
            nullifier_pdas
                .iter_mut()
                .zip(&ix.inputs)
                .filter(|(_, input)| input.tree_index == tree_index)
                .map(|(nullifier_pda, input)| (&mut **nullifier_pda, &input.nullifier_hash)),
            &result,
        )?;
        // 5. Retain its first queue sequence for the event.
        sequences.try_push(result.input_tree).map_err(|_| shape)?;
    }

    // 6. Assign the tree slots and packed input flags to the proof inputs.
    let input_flags = pack_input_flags(
        allow_dummy_inputs,
        ix.inputs.iter().map(|input| input.tree_index),
    )?;
    proof_inputs.assign_input_trees(tree_slots, input_flags);
    Ok(sequences)
}

pub(crate) fn resolve_input_tree_slot(
    input_tree: &TreeAccount<'_>,
    context: &TreeContext,
) -> Result<TreeSlot, ProgramError> {
    if context.utxo_tree_root_index != NO_UTXO_ROOT {
        return resolve_tree_slot(input_tree, context).map_err(tree_error);
    }
    Ok(TreeSlot {
        id: input_tree.tree_id_array(),
        utxo_root: [0; 32],
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
