use arrayvec::ArrayVec;
use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{Input, InputTreeSequence, SplTransfer, TransactEvent},
    instruction::instruction_data::transact::{ResolvedOutput, TransactIxDataRef},
};

use super::verify::MAX_OUTPUTS;
use crate::instructions::settlement::Settlement;

pub struct TreeWrite {
    pub inputs: Vec<Input>,
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

/// Build the emitted [`TransactEvent`]: the values assigned while writing the
/// trees plus the settled assets. Outputs, messages, nullifiers, `tx_viewing_pk`
/// and `salt` are not repeated; the indexer reads them from the instruction data
/// when it rebuilds the `GeneralEvent`.
pub fn build_transact_event(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
    tree_write: TreeWrite,
) -> Result<TransactEvent, ProgramError> {
    let first_input = tree_write
        .inputs
        .first()
        .ok_or(ShieldedPoolError::InvalidTransactShape)?;

    let spl_transfers = ix
        .interface_transfers
        .iter()
        .zip(settlements.iter())
        .map(|(transfer, settlement)| SplTransfer {
            is_deposit: transfer.is_deposit(),
            amount: transfer.amount(),
            asset: match settlement {
                Settlement::SolDeposit(_) | Settlement::SolWithdrawal(_) => None,
                Settlement::SplDeposit(spl) => Some(spl.mint_account.address().to_bytes()),
                Settlement::SplWithdrawal(spl) => Some(spl.mint_account.address().to_bytes()),
            },
        })
        .collect();

    Ok(TransactEvent {
        input_trees: vec![InputTreeSequence {
            tree: first_input.tree,
            first_input_queue_seq: first_input.input_queue_seq,
        }],
        output_tree: tree_write.output_tree,
        first_output_leaf_index: tree_write.first_output_leaf_index,
        spl_transfers,
    })
}
