use light_program_profiler::profile;
use pinocchio::ProgramResult;
use zolana_interface::{
    event::{
        encode_output_data, DepositWithdraw, EventKind, GeneralEvent, OutputData, ProoflessOutput,
    },
    instruction::OutputUtxo,
};

use super::processor::DepositParams;
use crate::instructions::event::emit_general_event;

/// Settlement-derived values the event needs but the request does not carry.
pub(crate) struct ProoflessOutputCtx {
    pub utxo_hash: [u8; 32],
    /// Deposited asset: the SPL mint, or all-zero for native SOL.
    pub asset: [u8; 32],
    pub needs_spl: bool,
    pub amount: u64,
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

#[profile]
pub(crate) fn emit_proofless_event(d: DepositParams, ctx: ProoflessOutputCtx) -> ProgramResult {
    let output_data = encode_output_data(&OutputData::Proofless(ProoflessOutput {
        owner: d.owner,
        blinding: d.blinding,
        asset: ctx.asset,
        amount: ctx.amount,
        program_data_hash: d.program_data_hash,
        program_data: d.program_data,
        zone_program_id: d.cpi_signer.map(|cpi| cpi.program_id),
        policy_data_hash: d.policy_data_hash,
        zone_data: d.zone_data,
    }));
    let event = GeneralEvent {
        inputs: Vec::new(),
        outputs: vec![OutputUtxo {
            view_tag: d.view_tag,
            utxo_hash: ctx.utxo_hash,
            data: output_data,
        }],
        // Proofless shields are Solana-rail deposits with no shared P256 viewing
        // key; the field is zeroed so indexers skip ECDH decryption.
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
