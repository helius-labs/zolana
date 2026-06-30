use pinocchio::ProgramResult;
use zolana_interface::{
    event::{encode_output_data, DepositWithdraw, EventKind, GeneralEvent, ProoflessOutput},
    instruction::OutputUtxo,
};

use super::processor::DepositParams;
use crate::instructions::event::emit_general_event;

pub(crate) struct ProoflessOutputCtx {
    pub utxo_hash: [u8; 32],
    pub asset: [u8; 32],
    pub needs_spl: bool,
    pub amount: u64,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
    pub zone_program_id: Option<[u8; 32]>,
}

pub(crate) fn emit_proofless_event(d: DepositParams, ctx: ProoflessOutputCtx) -> ProgramResult {
    let (data_hash, utxo_data) = match d.utxo_data {
        Some(record) => (Some(record.data_hash), Some(record.data)),
        None => (None, None),
    };
    let (zone_data_hash, zone_data) = match d.zone {
        Some(zone) => (Some(zone.data_hash), Some(zone.data)),
        None => (None, None),
    };
    let output_data = encode_output_data(ProoflessOutput {
        owner: d.owner,
        blinding: d.blinding,
        asset: ctx.asset,
        amount: ctx.amount,
        data_hash,
        utxo_data,
        zone_program_id: ctx.zone_program_id,
        zone_data_hash,
        zone_data,
    });
    let event = GeneralEvent {
        inputs: Vec::new(),
        outputs: vec![OutputUtxo {
            view_tag: d.view_tag,
            utxo_hash: ctx.utxo_hash,
            data: output_data,
        }],
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: ctx.first_output_leaf_index,
        output_tree: ctx.output_tree,
        relay_fee: None,
        deposit_withdraw: Some(DepositWithdraw {
            is_deposit: true,
            amount: ctx.amount,
            asset: ctx.needs_spl.then_some(ctx.asset),
        }),
    };
    emit_general_event(EventKind::Deposit, event)
}
