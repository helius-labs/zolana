pub mod output_utxo;
#[cfg(feature = "program-test")]
pub mod reconstruction;

use borsh::{BorshDeserialize, BorshSerialize};
pub use output_utxo::OutputUtxo;
use zolana_interface::instruction::{tag, MessageData};

/// `GeneralEvent`, emitted via the `emit_event` self-CPI by state-changing
/// instructions (spec: General Event). It records the queue sequence numbers and
/// leaf indices assigned at execution, which are absent from instruction data,
/// so an indexer can reconstruct nullifier insertions and UTXO appends.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct GeneralEvent {
    pub inputs: Vec<Input>,
    pub outputs: Vec<OutputUtxo>,
    /// Published data slots bound to no output position, republished from
    /// `TransactIxData::messages`.
    pub messages: Vec<MessageData>,
    /// SEC1-compressed P256 viewing key shared by every output ciphertext, so an
    /// indexer can decrypt without parsing the per-output `data`. Zeroed for
    /// proofless deposits, which have no shared viewing key.
    pub tx_viewing_pk: [u8; 33],
    /// Per-transaction encryption salt shared by every output ciphertext, so a
    /// wallet can derive the AES key/nonce without parsing the per-output `data`.
    /// Zeroed for proofless deposits, which have no shared salt.
    pub salt: [u8; 16],
    /// Leaf index of `outputs[0]`; later outputs append sequentially.
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
    /// Per-asset public SPL transfers: empty for a shielded transfer, one entry per
    /// settled interface transfer. A batched `deposit` carries one entry per deposited
    /// asset.
    pub spl_transfers: Vec<SplTransfer>,
}

/// One spent input. Every emitter queues its nullifiers into a single input
/// tree, so `tree` is constant across an event's inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Input {
    pub tree: [u8; 32],
    pub input_queue_seq: u64,
    pub nullifier: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct SplTransfer {
    pub is_deposit: bool,
    pub amount: u64,
    pub asset: Option<[u8; 32]>,
}

/// Body of the `EMIT_EVENT` self-CPI for `transact`, `ring_transact` and
/// `ring_authority_transact`.
///
/// Carries only what execution assigns and instruction data cannot express. An
/// indexer reconstructs nullifiers, outputs, messages, trees and settlement legs
/// from the parent instruction and its account list. Queue sequences and leaf
/// indices are contiguous within a transaction -- both are single monotone
/// counters incremented once per insert, over one input tree and one output tree
/// in instruction-data order -- so entry `i` sits at `first_* + i`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct TransactEvent {
    pub first_input_queue_seq: u64,
    pub first_output_leaf_index: u64,
}

impl TransactEvent {
    /// Borsh encodes fixed-size fields as their little-endian concatenation, so
    /// the whole body is this many bytes and can be written into a stack array.
    pub const LEN: usize = 16;
}

/// Body of the `EMIT_EVENT` self-CPI for `merge_transact` and
/// `ring_merge_transact`.
///
/// `output_view_tag` is retained because `merge_transact` reads it from the
/// `user_record` account rather than from instruction data, and an indexer
/// cannot re-read that account at the historical slot. `ring_merge_transact`
/// derives its tag from `nullifiers[0]` instead, so it writes zero here and the
/// reconstructor dispatches on the parent instruction tag, never on this value.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct MergeEvent {
    pub first_input_queue_seq: u64,
    pub first_output_leaf_index: u64,
    pub output_view_tag: [u8; 32],
}

impl MergeEvent {
    pub const LEN: usize = 48;
}

/// First payload byte after `EMIT_EVENT`: names the emitting instruction so an
/// indexer can dispatch (and version) the borsh body without trial-parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    Deposit = 1,
    Transact = 2,
    Merge = 3,
    /// Nullifier-tree batch update. Body is a
    /// `zolana_tree::NullifierTreeUpdateEvent` (one cascade event per update),
    /// not a [`GeneralEvent`].
    NullifierTreeUpdate = 4,
}

impl EventKind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Deposit),
            2 => Some(Self::Transact),
            3 => Some(Self::Merge),
            4 => Some(Self::NullifierTreeUpdate),
            _ => None,
        }
    }

    /// Event kind emitted by a state-changing shielded-pool instruction.
    pub fn for_source_instruction(source_instruction_tag: u8) -> Option<Self> {
        match source_instruction_tag {
            tag::DEPOSIT | tag::RING_DEPOSIT => Some(Self::Deposit),
            tag::TRANSACT | tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT => {
                Some(Self::Transact)
            }
            tag::MERGE_TRANSACT | tag::RING_MERGE_TRANSACT => Some(Self::Merge),
            tag::BATCH_UPDATE_NULLIFIER_TREE => Some(Self::NullifierTreeUpdate),
            _ => None,
        }
    }
}

/// Encode a full proofless-deposit event as an `EMIT_EVENT` instruction.
pub fn encode_deposit_event(event: &GeneralEvent) -> Vec<u8> {
    encode_variable_event(EventKind::Deposit, event)
}

/// Encode a nullifier-tree update event as an `EMIT_EVENT` instruction.
#[cfg(feature = "nullifier-tree")]
pub fn encode_nullifier_tree_update_event(
    event: &zolana_tree::NullifierTreeUpdateEvent,
) -> Vec<u8> {
    encode_variable_event(EventKind::NullifierTreeUpdate, event)
}

fn encode_variable_event<T: BorshSerialize>(kind: EventKind, payload: &T) -> Vec<u8> {
    let mut data = vec![tag::EMIT_EVENT, kind as u8];
    payload
        .serialize(&mut data)
        .expect("shielded-pool event serialization is infallible");
    data
}

/// Encode an `EMIT_EVENT` instruction whose body is a fixed-size event, into a
/// stack array rather than a `Vec`.
///
/// Layout is `[EMIT_EVENT, kind, body]`. The
/// body is little-endian, which is exactly what Borsh writes for these all
/// fixed-size structs, so the two encodings agree byte for byte.
pub fn encode_transact_event(event: &TransactEvent) -> [u8; 2 + TransactEvent::LEN] {
    let mut out = [0u8; 2 + TransactEvent::LEN];
    out[0] = tag::EMIT_EVENT;
    out[1] = EventKind::Transact as u8;
    out[2..10].copy_from_slice(&event.first_input_queue_seq.to_le_bytes());
    out[10..18].copy_from_slice(&event.first_output_leaf_index.to_le_bytes());
    out
}

/// See [`encode_transact_event`]; same layout with the retained output view tag.
pub fn encode_merge_event(event: &MergeEvent) -> [u8; 2 + MergeEvent::LEN] {
    let mut out = [0u8; 2 + MergeEvent::LEN];
    out[0] = tag::EMIT_EVENT;
    out[1] = EventKind::Merge as u8;
    out[2..10].copy_from_slice(&event.first_input_queue_seq.to_le_bytes());
    out[10..18].copy_from_slice(&event.first_output_leaf_index.to_le_bytes());
    out[18..50].copy_from_slice(&event.output_view_tag);
    out
}

// Decode and indexer-reconstruction helpers used by indexers (the in-repo
// program-test harness and Photon) and by wallet deposit discovery, but never
// by the on-chain program, which only emits events.
#[cfg(feature = "program-test")]
mod program_test;

#[cfg(feature = "program-test")]
pub use program_test::*;
