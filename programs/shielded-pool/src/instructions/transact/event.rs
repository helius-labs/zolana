use arrayvec::ArrayVec;
use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError,
    event::TransactEvent,
    instruction::instruction_data::transact::{ResolvedOutput, TransactIxDataRef},
};

use super::verify::MAX_OUTPUTS;
use crate::instructions::nullifier_pda::InputTreeResult;

pub struct TreeWrite {
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
    /// Raw id of `output_tree`; every output is hashed under it, so the proof
    /// commits to it as a public input.
    pub output_tree_id: u16,
}

#[inline(never)]
pub(crate) fn resolve_outputs<'a>(
    accounts: &[AccountView],
    ix: &TransactIxDataRef<'a>,
) -> Result<ArrayVec<ResolvedOutput<'a>, MAX_OUTPUTS>, ProgramError> {
    let mut outputs = ArrayVec::new(); // TODO: check whether we really need this allocation.
    for output in &ix.outputs {
        let resolved = output
            .into_resolved(|i| accounts.get(usize::from(i)).map(|a| a.address().to_bytes()))?;
        outputs
            .try_push(resolved)
            .map_err(|_| ShieldedPoolError::InvalidTransactShape)?;
    }
    Ok(outputs)
}

/// Build the emitted [`TransactEvent`]: the trees and the values assigned while
/// writing them. Everything else the indexer reads from the instruction data
/// and account list when it rebuilds the `GeneralEvent`.
///
/// `input_tree_results` is in declared-context order, so an input's queue
/// number is its tree's `first_input_queue_seq` plus its rank within that
/// tree's input run.
pub fn build_transact_event(
    tree_write: TreeWrite,
    input_tree_results: &[InputTreeResult],
) -> TransactEvent {
    TransactEvent {
        input_trees: input_tree_results
            .iter()
            .map(|result| result.input_tree)
            .collect(),
        output_tree: tree_write.output_tree,
        first_output_leaf_index: tree_write.first_output_leaf_index,
    }
}
