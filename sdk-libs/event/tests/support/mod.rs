//! Builders for the two reconstruction inputs: a source instruction carrying real
//! wincode instruction data, and the `EMIT_EVENT` self-CPI it produced.

use borsh::BorshSerialize;
use solana_pubkey::Pubkey;
use zolana_event::{encode_event_instruction, EventKind, InputTreeSequence, MergeEvent};
use zolana_event_parser::ParsedInstruction;
use zolana_interface::instruction::{
    instruction_data::merge_transact::{MergeProof, MERGE_INPUT_COUNT},
    CircuitId, InputUtxo, InterfaceTransfer, MergeRingIxData, MergeTransactIxData, MessageData,
    TransactIxData, TransactOutput, TransactProof,
};

pub const INPUT_TREE: [u8; 32] = [1u8; 32];
pub const OUTPUT_TREE: [u8; 32] = [2u8; 32];
pub const TX_VIEWING_PK: [u8; 33] = [5u8; 33];
pub const SALT: [u8; 16] = [6u8; 16];

pub fn transact_ix(
    inputs: Vec<InputUtxo>,
    outputs: Vec<TransactOutput>,
    messages: Vec<MessageData>,
    interface_transfers: Vec<InterfaceTransfer>,
) -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: 0,
        private_tx_hash: [7u8; 32],
        circuit: CircuitId::ConfidentialEddsa(
            u8::try_from(inputs.len()).expect("test shape"),
            u8::try_from(outputs.len()).expect("test shape"),
            0,
        ),
        tx_viewing_pk: TX_VIEWING_PK,
        salt: SALT,
        proof: TransactProof::zeroed(),
        inputs,
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs,
        messages,
    }
}

pub fn merge_ix(output_utxo_hash: [u8; 32]) -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: 0,
        proof: MergeProof::zeroed(),
        output_utxo_hash,
        eddsa_owner: true,
        private_tx_hash: [7u8; 32],
        nullifiers: (0..MERGE_INPUT_COUNT)
            .map(|i| [0x40 + u8::try_from(i).expect("test shape"); 32])
            .collect(),
        utxo_tree_root_index: vec![0; MERGE_INPUT_COUNT],
        nullifier_tree_root_index: vec![0; MERGE_INPUT_COUNT],
    }
}

pub fn merge_ring_ix(
    output_utxo_hash: [u8; 32],
    output_ring_data_hash: [u8; 32],
) -> MergeRingIxData {
    MergeRingIxData {
        output_ring_data_hash,
        merge: merge_ix(output_utxo_hash),
    }
}

/// A source instruction `[tag] ++ ix_bytes` at the given stack height.
pub fn source(
    program_id: Pubkey,
    tag: u8,
    accounts: Vec<Pubkey>,
    ix_bytes: Vec<u8>,
    stack_height: u32,
) -> ParsedInstruction {
    let mut data = vec![tag];
    data.extend_from_slice(&ix_bytes);
    ParsedInstruction::new(program_id, accounts, data, stack_height)
}

pub fn transact_source(
    program_id: Pubkey,
    tag: u8,
    accounts: Vec<Pubkey>,
    ix: &TransactIxData,
    stack_height: u32,
) -> ParsedInstruction {
    source(
        program_id,
        tag,
        accounts,
        ix.serialize().expect("serialize transact"),
        stack_height,
    )
}

pub fn emit_event_data<T: BorshSerialize>(kind: EventKind, body: &T) -> Vec<u8> {
    encode_event_instruction(kind, body)
}

/// The `EMIT_EVENT` self-CPI one level below its source.
pub fn emit_instruction<T: BorshSerialize>(
    program_id: Pubkey,
    kind: EventKind,
    body: &T,
    stack_height: u32,
) -> ParsedInstruction {
    ParsedInstruction::new(
        program_id,
        Vec::new(),
        emit_event_data(kind, body),
        stack_height,
    )
}

pub fn input_trees(first_input_queue_seq: u64) -> Vec<InputTreeSequence> {
    vec![InputTreeSequence {
        tree: INPUT_TREE,
        first_input_queue_seq,
    }]
}

pub fn merge_event(output_view_tag: [u8; 32]) -> MergeEvent {
    MergeEvent {
        input_trees: input_trees(20),
        output_tree: OUTPUT_TREE,
        output_leaf_index: 9,
        output_view_tag,
    }
}
