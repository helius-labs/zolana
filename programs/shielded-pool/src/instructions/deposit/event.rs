use pinocchio::ProgramResult;
use zolana_interface::{
    event::{encode_output_data, EventKind, GeneralEvent, Movement, ProoflessOutput},
    instruction::{DepositEntry, OutputUtxo},
};

use super::processor::ZoneData;
use crate::instructions::event::emit_general_event;

pub(crate) struct ProoflessOutputCtx {
    pub utxo_hash: [u8; 32],
    pub asset: [u8; 32],
    pub zone_program_id: Option<[u8; 32]>,
}

pub(crate) fn proofless_output_utxo(
    entry: DepositEntry,
    zone: Option<ZoneData>,
    ctx: ProoflessOutputCtx,
) -> OutputUtxo {
    let (data_hash, utxo_data) = match entry.utxo_data {
        Some(record) => (Some(record.data_hash), Some(record.data)),
        None => (None, None),
    };
    let (zone_data_hash, zone_data) = match zone {
        Some(zone) => (Some(zone.data_hash), Some(zone.data)),
        None => (None, None),
    };
    let data = encode_output_data(ProoflessOutput {
        owner: entry.owner,
        blinding: entry.blinding,
        asset: ctx.asset,
        amount: entry.amount,
        data_hash,
        utxo_data,
        zone_program_id: ctx.zone_program_id,
        zone_data_hash,
        zone_data,
        memo: entry.memo,
    });
    OutputUtxo {
        view_tag: entry.view_tag,
        utxo_hash: ctx.utxo_hash,
        data,
    }
}

pub(crate) struct DepositEvent {
    pub outputs: Vec<OutputUtxo>,
    pub movements: Vec<Movement>,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

pub(crate) fn emit_deposit_event(e: DepositEvent) -> ProgramResult {
    let event = GeneralEvent {
        inputs: Vec::new(),
        outputs: e.outputs,
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: e.first_output_leaf_index,
        output_tree: e.output_tree,
        movements: e.movements,
    };
    emit_general_event(EventKind::Deposit, event)
}
