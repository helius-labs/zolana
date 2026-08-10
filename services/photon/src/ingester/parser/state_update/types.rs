use crate::common::rings_tree::RingsTreeKind;
use crate::ingester::parser::tree_info::TreeInfo;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use std::collections::{HashMap, HashSet};

#[derive(Hash, Eq, Clone, PartialEq, Debug)]
pub struct Transaction {
    pub signature: Signature,
    pub slot: u64,
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct RawIndexedElement {
    pub value: [u8; 32],
    pub next_index: usize,
    pub next_value: [u8; 32],
    pub index: usize,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct IndexedTreeLeafUpdate {
    pub tree: Pubkey,
    pub tree_kind: RingsTreeKind,
    pub leaf: RawIndexedElement,
    pub hash: [u8; 32],
    pub seq: u64,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingsOutputUpdate {
    pub output_index: i16,
    pub output_tree: [u8; 32],
    pub leaf_index: u64,
    pub view_tag: [u8; 32],
    pub utxo_hash: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingsMessageUpdate {
    pub message_index: i16,
    pub view_tag: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingsNullifierUpdate {
    pub input_index: i16,
    pub nullifier_tree: [u8; 32],
    pub input_queue_seq: u64,
    pub nullifier: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullifierTreeBatchUpdate {
    pub tree: Pubkey,
    pub new_root: [u8; 32],
    /// Zkp batches the instruction settles. A fold settles several of them
    /// against one root, so `new_root` is the root after all of them and the
    /// reconstruction must apply every one before it compares.
    pub run: u32,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingsTransactionUpdate {
    pub signature: Signature,
    pub event_index: i16,
    pub slot: u64,
    pub rings_program_id: [u8; 32],
    pub source_instruction_tag: i16,
    pub output_tree: [u8; 32],
    pub first_output_leaf_index: u64,
    pub tx_viewing_pk: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
    pub proofless: bool,
    pub encrypted_utxos: Option<Vec<u8>>,
    pub raw_event: Option<Vec<u8>>,
    pub parse_version: i16,
    pub outputs: Vec<RingsOutputUpdate>,
    pub messages: Vec<RingsMessageUpdate>,
    pub nullifiers: Vec<RingsNullifierUpdate>,
}

/// One Squads ring key-material event. The scalar fields identify and order the
/// event, `raw_event` carries the destroyed key material as the program encoded
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquadsKeyEventUpdate {
    pub signature: Signature,
    pub event_index: i16,
    pub slot: u64,
    pub squads_program_id: [u8; 32],
    pub source_instruction_tag: i16,
    pub event_kind: i16,
    pub account: [u8; 32],
    pub owner: [u8; 32],
    /// Nonce of the account state before the emitting instruction wrote it.
    pub key_nonce: u64,
    /// Nonce the rotation wrote. A close writes none.
    pub new_key_nonce: Option<u64>,
    /// Rotation commitment the proof was bound to. A close has none.
    pub old_state_hash: Option<[u8; 32]>,
    pub raw_event: Vec<u8>,
    pub parse_version: i16,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct StateUpdate {
    pub transactions: HashSet<Transaction>,
    pub rings_transactions: Vec<RingsTransactionUpdate>,
    pub squads_key_events: Vec<SquadsKeyEventUpdate>,
    pub nullifier_tree_batch_updates: Vec<NullifierTreeBatchUpdate>,
}

pub struct FilteredStateUpdate {
    pub state_update: StateUpdate,
    pub tree_info_cache: HashMap<Pubkey, TreeInfo>,
}

impl StateUpdate {
    pub fn new() -> Self {
        StateUpdate::default()
    }

    pub fn merge_updates(updates: Vec<StateUpdate>) -> StateUpdate {
        let mut merged = StateUpdate::default();

        for update in updates {
            merged.transactions.extend(update.transactions);
            merged.rings_transactions.extend(update.rings_transactions);
            merged.squads_key_events.extend(update.squads_key_events);
            merged
                .nullifier_tree_batch_updates
                .extend(update.nullifier_tree_batch_updates);
        }

        merged
    }
}
