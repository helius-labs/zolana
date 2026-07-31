use pinocchio::ProgramResult;
use zolana_interface::{
    event::{
        encode_encrypted_zone_deposit_output_ref, encode_output_data_ref,
        EncryptedZoneDepositDataRef as EventEncryptedZoneDepositDataRef,
        EncryptedZoneDepositOutputRef, EventKind, GeneralEvent, ProoflessOutputRef, SplTransfer,
    },
    instruction::{DepositEntryRef, OutputUtxo, ZoneDepositEntryRef},
};

use crate::instructions::event::emit_general_event;

pub(crate) struct ProoflessOutputCtx {
    pub utxo_hash: [u8; 32],
    pub asset: [u8; 32],
}

pub(crate) fn proofless_output_utxo<'a>(
    entry: DepositEntryRef<'a>,
    ctx: ProoflessOutputCtx,
) -> OutputUtxo {
    let (data_hash, utxo_data) = match entry.utxo_data {
        Some(record) => (Some(record.data_hash), Some(record.data)),
        None => (None, None),
    };
    let data = encode_output_data_ref(ProoflessOutputRef {
        owner: entry.owner,
        blinding: entry.blinding,
        asset: &ctx.asset,
        amount: entry.amount,
        data_hash,
        utxo_data,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: entry.memo,
    });
    OutputUtxo {
        view_tag: *entry.view_tag,
        utxo_hash: ctx.utxo_hash,
        data,
    }
}

pub(crate) fn encrypted_zone_output_utxo(
    entry: ZoneDepositEntryRef<'_>,
    ctx: ProoflessOutputCtx,
    zone_program_id: [u8; 32],
) -> OutputUtxo {
    let data = encode_encrypted_zone_deposit_output_ref(EncryptedZoneDepositOutputRef {
        owner_utxo_hash: entry.owner_utxo_hash,
        asset: &ctx.asset,
        amount: entry.amount,
        data_hash: entry.data_hash,
        zone_program_id: &zone_program_id,
        zone_data_hash: entry.zone_data_hash,
        encrypted: EventEncryptedZoneDepositDataRef {
            tx_viewing_pk: entry.encrypted.tx_viewing_pk,
            salt: entry.encrypted.salt,
            ciphertext: entry.encrypted.ciphertext,
        },
    });
    OutputUtxo {
        view_tag: *entry.view_tag,
        utxo_hash: ctx.utxo_hash,
        data,
    }
}

pub(crate) struct DepositEvent {
    pub outputs: Vec<OutputUtxo>,
    pub spl_transfers: Vec<SplTransfer>,
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
        spl_transfers: e.spl_transfers,
    };
    emit_general_event(EventKind::Deposit, event)
}
