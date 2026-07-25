use pinocchio::ProgramResult;
use zolana_interface::{
    error::ShieldedPoolError,
    event::{DepositWithdraw, EventKind, ProoflessEvent, ProoflessOutput, ProoflessOutputSlot},
    instruction::DepositEntry,
};

use super::processor::ZoneData;
use crate::instructions::event::emit_encoded_event;

pub(crate) struct ProoflessOutputCtx {
    pub utxo_hash: [u8; 32],
    pub asset: [u8; 32],
    pub zone_program_id: Option<[u8; 32]>,
}

pub(crate) fn proofless_output_slot(
    entry: DepositEntry,
    zone: Option<ZoneData>,
    ctx: ProoflessOutputCtx,
) -> ProoflessOutputSlot {
    let (data_hash, utxo_data) = match entry.utxo_data {
        Some(record) => (Some(record.data_hash), Some(record.data)),
        None => (None, None),
    };
    let (zone_data_hash, zone_data) = match zone {
        Some(zone) => (Some(zone.data_hash), Some(zone.data)),
        None => (None, None),
    };
    ProoflessOutputSlot {
        view_tag: entry.view_tag,
        utxo_hash: ctx.utxo_hash,
        output: ProoflessOutput {
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
        },
    }
}

pub(crate) struct DepositEvent<'a> {
    pub outputs: &'a [ProoflessOutputSlot],
    pub deposit_withdraws: &'a [DepositWithdraw],
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

/// Encode the event into one exactly-sized allocation and emit it, so no output's
/// plaintext is written to an intermediate buffer first.
pub(crate) fn emit_deposit_event(e: DepositEvent<'_>) -> ProgramResult {
    let encoded = ProoflessEvent {
        outputs: e.outputs,
        deposit_withdraws: e.deposit_withdraws,
        first_output_leaf_index: e.first_output_leaf_index,
        output_tree: e.output_tree,
    }
    .encode(EventKind::Deposit)
    .map_err(|_| ShieldedPoolError::EventEncodingOverflow)?;
    emit_encoded_event(&encoded)
}
