use crate::instructions::shared::caused_by;
use arrayvec::ArrayVec;
use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_interface::{
    error::ShieldedPoolError,
    event::InputTreeSequence,
    instruction::instruction_data::transact::{TransactIxDataRef, TreeContext},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    tree_slot::{pack_input_flags, TreeSlot},
    INPUT_TREES,
};
use zolana_tree::TreeAccount;

use super::{account::TransactAccounts, event::TreeWrite, verify::TransactProofInputs};
use crate::instructions::{
    cache::loader::load_cache_mut,
    nullifier_pda::{create_nullifier_pdas, InputTreeResult},
    shared::tree_error,
};

/// Resolve every declared input tree's roots into its proof tree slot, assign
/// the slots with the packed input flags, queue each tree's nullifiers and
/// create their PDAs. Retain only the queue metadata needed by the event.
///
/// Steps 1-5 complete each tree before moving to the next:
/// 1. Select the tree's contiguous input group.
/// 2. Load the tree, combine its dummy-input policy and resolve its roots.
/// 3. Queue its nullifiers and credit its insertion fee.
/// 4. Release the tree-data borrow, collect the fee and create its PDAs.
/// 5. Retain its first queue sequence for the event.
/// 6. Reject unmatched tree contexts, input groups or PDA accounts.
/// 7. Assign the tree slots and packed input flags to the proof inputs.
///
/// Inputs are grouped by tree, so each tree owns one contiguous group of inputs.
/// The tree library assigns consecutive queue numbers within each group. The
/// circuit applies its single dummy-input bit to every input slot whichever
/// tree it selected, so the published policy is the conjunction over all input
/// trees: anything weaker would relax the gate of the tightest tree.
#[profile]
pub(crate) fn apply_input_trees(
    accounts: &mut TransactAccounts<'_>,
    ix: &TransactIxDataRef<'_>,
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
    let mut remaining_pdas = nullifier_pdas.as_mut_slice();

    let mut input_groups = ix
        .inputs
        .chunk_by(|left, right| left.tree_index == right.tree_index);
    let mut input_offset = 0usize;
    for (input_tree_account, context) in input_trees.iter_mut().zip(&ix.tree_contexts) {
        // 1. Select the tree's contiguous input group.
        let tree_inputs = input_groups.next().ok_or(shape)?;
        let input_end = input_offset.checked_add(tree_inputs.len()).ok_or(shape)?;
        let requires_state_root = ix
            .circuit
            .cached_inputs()
            .is_none_or(|selection| (input_offset..input_end).any(|i| !selection.selects(i)));
        input_offset = input_end;
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
                input_tree.dummy_input_headroom().map_err(tree_error)? >= tree_inputs.len() as u64;
            tree_slots
                .try_push(resolve_input_tree_slot(
                    &input_tree,
                    context,
                    requires_state_root,
                )?)
                .map_err(|_| shape)?;

            // 3. Queue its nullifiers and credit its insertion fee.
            let first_input_queue_seq = input_tree.nullifier_tree().queue_next_index;
            for input in tree_inputs {
                input_tree
                    .nullifier_tree()
                    .insert_nullifier_into_queue(&input.nullifier_hash)
                    .map_err(caused_by(ShieldedPoolError::NullifierTreeUpdateFailed))?;
            }
            let forester_fee = input_tree
                .credit_insertion_fee(tree_inputs.len() as u64)
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
        let (tree_pdas, rest) = remaining_pdas
            .split_at_mut_checked(tree_inputs.len())
            .ok_or(ShieldedPoolError::InvalidNullifierPda)?;
        create_nullifier_pdas(
            payer,
            input_tree_account,
            tree_pdas,
            tree_inputs.iter().map(|input| &input.nullifier_hash),
            &result,
        )?;
        remaining_pdas = rest;
        // 5. Retain its first queue sequence for the event.
        sequences.try_push(result.input_tree).map_err(|_| shape)?;
    }
    // 6. Every declared context must have been paired with both a tree account
    // and an input group; leftover groups or mismatched counts mean the
    // instruction data and the account list disagree.
    if input_groups.next().is_some()
        || sequences.len() != ix.tree_contexts.len()
        || sequences.len() != input_trees.len()
    {
        return Err(shape.into());
    }
    if !remaining_pdas.is_empty() {
        return Err(ShieldedPoolError::InvalidNullifierPda.into());
    }

    // 7. Assign the tree slots and packed input flags to the proof inputs.
    let input_flags = pack_input_flags(
        allow_dummy_inputs,
        ix.inputs.iter().map(|input| input.tree_index),
    )?;
    proof_inputs.assign_input_trees(tree_slots, input_flags);
    Ok(sequences)
}

/// One populated tree slot: the tree's id and the roots at its context's
/// root-index pair.
pub(crate) fn resolve_input_tree_slot(
    input_tree: &TreeAccount<'_>,
    context: &TreeContext,
    requires_state_root: bool,
) -> Result<TreeSlot, ProgramError> {
    Ok(TreeSlot {
        id: input_tree.tree_id_array(),
        utxo_root: if requires_state_root {
            input_tree
                .get_utxo_tree_root(context.utxo_tree_root_index)
                .map_err(tree_error)?
        } else {
            // Every input in this group proves a cached commitment. The circuit's
            // bitmap skips state inclusion; zero canonically encodes the unused root.
            // Cache commitments outlive state-root history, but each spend still
            // requires an existing cache, a valid nullifier root and an unexpired tx.
            if context.utxo_tree_root_index != 0 {
                return Err(ShieldedPoolError::InvalidCacheRootIndex.into());
            }
            [0; 32]
        },
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

/// Load once, bind the cached inputs, and freeze further merge insertions.
/// Proof or settlement failure rolls back the flag along with tree mutations.
#[profile]
pub(crate) fn apply_cached_inputs(
    account: &mut AccountView,
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &mut TransactProofInputs,
) -> ProgramResult {
    let mut cache = load_cache_mut(account)?;
    proof_inputs.assign_cached_inputs(ix, &cache)?;
    cache.frozen = 1;
    Ok(())
}
