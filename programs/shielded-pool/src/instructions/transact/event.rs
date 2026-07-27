use arrayvec::ArrayVec;
use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::{
    error::ShieldedPoolError,
    event::{GeneralEvent, Input, MessageData, Movement},
    instruction::{
        instruction_data::transact::{ResolvedOutput, TransactIxDataRef},
        OutputUtxo,
    },
};

use super::verify::MAX_OUTPUTS;
use crate::instructions::settlement::Settlement;

pub struct TreeWrite {
    pub inputs: Vec<Input>,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
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

/// Build the emitted [`GeneralEvent`] from the instruction. Outputs map 1:1 to
/// `ix.outputs`: each event output carries the resolved owner tag as its
/// `view_tag`, the output commitment, and the optional ciphertext (empty when the
/// slot is covered by a preceding bundle). `messages` are republished verbatim.
pub fn build_transact_event(
    ix: &TransactIxDataRef<'_>,
    settlements: &[Settlement<'_>],
    tree_write: TreeWrite,
    resolved_outputs: &[ResolvedOutput],
) -> GeneralEvent {
    let outputs = resolved_outputs
        .iter()
        .map(|output| OutputUtxo {
            view_tag: output.owner_tag,
            utxo_hash: *output.utxo_hash,
            data: output.data.map(<[u8]>::to_vec).unwrap_or_default(),
        })
        .collect();

    let messages = ix
        .messages
        .iter()
        .map(|message| MessageData {
            view_tag: *message.view_tag,
            data: message.data.to_vec(),
        })
        .collect();

    let interface_transfers = ix
        .interface_transfers
        .iter()
        .zip(settlements.iter())
        .map(|(transfer, settlement)| Movement {
            is_deposit: transfer.is_deposit(),
            amount: transfer.amount(),
            asset: match settlement {
                Settlement::Sol(_) => None,
                Settlement::SplDeposit(spl) => Some(spl.mint_account.address().to_bytes()),
                Settlement::SplWithdrawal(spl) => Some(spl.mint_account.address().to_bytes()),
            },
        })
        .collect();

    GeneralEvent {
        inputs: tree_write.inputs,
        outputs,
        messages,
        tx_viewing_pk: *ix.tx_viewing_pk,
        salt: *ix.salt,
        first_output_leaf_index: tree_write.first_output_leaf_index,
        output_tree: tree_write.output_tree,
        movements: interface_transfers,
    }
}
