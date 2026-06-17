use zolana_interface::{
    event::{DepositWithdraw, GeneralEvent, Input},
    instruction::{
        instruction_data::transact::{OutputUtxoRef, TransactIxDataRef},
        OutputUtxo,
    },
};

use super::verify::TransactProofInputs;

pub struct TreeWrite {
    pub inputs: Vec<Input>,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

pub fn build_transact_event(
    ix: &TransactIxDataRef<'_>,
    proof_inputs: &TransactProofInputs,
    tree_write: TreeWrite,
) -> GeneralEvent {
    let mut outputs = Vec::with_capacity(1 + ix.recipient_utxo_data.len());
    outputs.push(output_utxo(&ix.sender_utxo_data));
    for recipient in &ix.recipient_utxo_data {
        outputs.push(output_utxo(recipient));
    }

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
        tx_viewing_pk: *ix.tx_viewing_pk,
        first_output_leaf_index: tree_write.first_output_leaf_index,
        output_tree: tree_write.output_tree,
        relay_fee: (ix.relayer_fee != 0).then_some(u64::from(ix.relayer_fee)),
        deposit_withdraw,
    }
}

fn output_utxo(slot: &OutputUtxoRef<'_>) -> OutputUtxo {
    OutputUtxo {
        view_tag: *slot.view_tag,
        utxo_hash: *slot.utxo_hash,
        data: slot.data.to_vec(),
    }
}
