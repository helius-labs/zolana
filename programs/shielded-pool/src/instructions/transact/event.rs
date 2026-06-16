use borsh::BorshSerialize;
use pinocchio::{cpi::invoke, instruction::InstructionView, AccountView, ProgramResult};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{OutputUtxoRef, TransactIxDataRef},
        tag::EMIT_EVENT,
        OutputUtxo,
    },
    transact_event::{DepositWithdraw, GeneralEvent, Input},
};

use super::verify::TransactProofInputs;
use crate::error::ShieldedPoolError;

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

pub fn emit_event(event: &GeneralEvent) -> ProgramResult {
    const TRANSACT_EVENT_KIND: u8 = 2;
    let mut data = vec![EMIT_EVENT, TRANSACT_EVENT_KIND];
    event
        .serialize(&mut data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let instruction_accounts = [];
    let instruction = InstructionView {
        program_id: &crate::ID,
        accounts: &instruction_accounts,
        data: &data,
    };
    let accounts: [&AccountView; 0] = [];
    invoke(&instruction, &accounts)
}
