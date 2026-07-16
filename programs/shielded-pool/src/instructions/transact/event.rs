use zolana_interface::{
    event::{DepositWithdraw, GeneralEvent, Input, MessageData},
    instruction::{
        instruction_data::transact::{ResolvedOutput, TransactIxDataRef},
        OutputUtxo,
    },
};

use super::verify::TransactProofInputs;

pub struct TreeWrite {
    pub inputs: Vec<Input>,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

/// Build the emitted [`GeneralEvent`] from the instruction. Outputs map 1:1 to
/// `ix.outputs`: each event output carries the resolved owner tag as its
/// `view_tag`, the output commitment, and the optional ciphertext (empty when the
/// slot is covered by a preceding bundle). `messages` are republished verbatim.
pub fn build_transact_event(
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &TransactProofInputs,
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

    let deposit_withdraw = ix.is_deposit_or_withdrawal().then(|| DepositWithdraw {
        is_deposit: ix.is_deposit(),
        amount: ix
            .public_spl_amount
            .or(ix.public_sol_amount)
            .unwrap_or(0)
            .unsigned_abs(),
        asset: proof_inputs.spl_mint,
    });

    GeneralEvent {
        inputs: tree_write.inputs,
        outputs,
        messages,
        tx_viewing_pk: *ix.tx_viewing_pk,
        salt: *ix.salt,
        first_output_leaf_index: tree_write.first_output_leaf_index,
        output_tree: tree_write.output_tree,
        relay_fee: (ix.relayer_fee != 0).then_some(u64::from(ix.relayer_fee)),
        deposit_withdraw,
    }
}
