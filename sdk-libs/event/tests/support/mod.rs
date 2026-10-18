//! Builders for the two reconstruction inputs: a source instruction carrying real
//! wincode instruction data, and the `EMIT_EVENT` self-CPI it produced.

use borsh::BorshSerialize;
use solana_pubkey::Pubkey;
use zolana_event::{encode_event_instruction, EventKind, InputTreeSequence, MergeEvent};
use zolana_event_parser::ParsedInstruction;
use zolana_interface::instruction::{
    instruction_data::merge_transact::{MergeProof, MERGE_DEFAULT_INPUT_COUNT},
    CircuitId, InputUtxo, InterfaceTransfer, MergeRingIxData, MergeTransactIxData, MessageData,
    TransactIxData, TransactOutput, TransactProof, TreeContext,
};

pub const INPUT_TREE: [u8; 32] = [1u8; 32];
pub const OUTPUT_TREE: [u8; 32] = [2u8; 32];
pub const TX_VIEWING_PK: [u8; 33] = [5u8; 33];
pub const SALT: [u8; 16] = [6u8; 16];

/// One context per tree the inputs name, so any grouping a test writes
/// serializes. Reconstruction reads the trees from the event, never the root
/// indexes, so they stay zero.
fn tree_contexts(inputs: &[InputUtxo]) -> Vec<TreeContext> {
    let count = inputs
        .iter()
        .map(|input| usize::from(input.tree_index).saturating_add(1))
        .max()
        .unwrap_or(1);
    vec![
        TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        };
        count
    ]
}

pub fn transact_ix(
    inputs: Vec<InputUtxo>,
    outputs: Vec<TransactOutput>,
    messages: Vec<MessageData>,
    interface_transfers: Vec<InterfaceTransfer>,
) -> TransactIxData {
    let tree_contexts = tree_contexts(&inputs);
    TransactIxData {
        expiry_unix_ts: 0,
        private_tx_hash: [7u8; 32],
        circuit: CircuitId::ConfidentialEd25519(
            u8::try_from(inputs.len()).expect("test shape"),
            u8::try_from(outputs.len()).expect("test shape"),
            0,
        ),
        tx_viewing_pk: TX_VIEWING_PK,
        salt: SALT,
        proof: TransactProof::zeroed(),
        inputs,
        tree_contexts,
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs,
        messages,
    }
}

pub const MERGE_CIPHERTEXT_SALT: [u8; 16] = [0x5a; 16];

pub const MERGE_CIPHERTEXT: [[u8; 32]; 3] = [[0x61; 32], [0x62; 32], [0x63; 32]];

/// The data slot a rebuilt merge output carries, spelled out byte by byte:
/// borsh `OutputDataEncoding::VerifiablyEncrypted` (variant 2, u32 LE length),
/// scheme 6, the `merge_ring` output ring data hash, the salt, the ciphertext.
pub fn merge_output_data(ring_data_hash: Option<[u8; 32]>) -> Vec<u8> {
    let mut blob = vec![6u8];
    if let Some(ring_data_hash) = ring_data_hash {
        blob.extend_from_slice(&ring_data_hash);
    }
    blob.extend_from_slice(&MERGE_CIPHERTEXT_SALT);
    for element in MERGE_CIPHERTEXT {
        blob.extend_from_slice(&element);
    }
    let mut data = vec![2u8];
    data.extend_from_slice(&u32::try_from(blob.len()).expect("blob").to_le_bytes());
    data.extend_from_slice(&blob);
    data
}

pub fn merge_ix(output_utxo_hash: [u8; 32]) -> MergeTransactIxData {
    MergeTransactIxData {
        cache_slot: None,
        expiry_unix_ts: 0,
        proof: MergeProof::zeroed(),
        output_utxo_hash,
        output_ciphertext_salt: MERGE_CIPHERTEXT_SALT,
        output_ciphertext: MERGE_CIPHERTEXT,
        eddsa_owner: true,
        private_tx_hash: [7u8; 32],
        nullifiers: (0..MERGE_DEFAULT_INPUT_COUNT)
            .map(|i| [0x40 + u8::try_from(i).expect("test shape"); 32])
            .collect(),
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    }
}

pub fn merge_ring_ix(
    output_utxo_hash: [u8; 32],
    output_ring_data_hash: [u8; 32],
) -> MergeRingIxData {
    MergeRingIxData {
        output_ring_data_hash,
        member_registry_root: [1; 32],
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

/// The event's input trees in the order the program applied them: entry `t` is
/// what an input with `tree_index == t` resolves against.
pub fn input_trees_in_order(
    trees: impl IntoIterator<Item = ([u8; 32], u64)>,
) -> Vec<InputTreeSequence> {
    trees
        .into_iter()
        .map(|(tree, first_input_queue_seq)| InputTreeSequence {
            tree,
            first_input_queue_seq,
        })
        .collect()
}

pub fn input_trees(first_input_queue_seq: u64) -> Vec<InputTreeSequence> {
    input_trees_in_order([(INPUT_TREE, first_input_queue_seq)])
}

pub fn merge_event(output_view_tag: [u8; 32]) -> MergeEvent {
    MergeEvent {
        input_trees: input_trees(20),
        output_tree: OUTPUT_TREE,
        output_leaf_index: 9,
        output_view_tag,
    }
}
