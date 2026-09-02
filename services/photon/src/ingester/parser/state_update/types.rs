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

/// One `NullifierTreeUpdateEvent`: the zkp batches the program actually applied,
/// which is not always the one its instruction asked for. An out-of-order proof
/// is cached and applied later, so a single instruction can land several batches
/// at once -- `num_update` of them, `zkp_batch_size` nullifiers each -- and
/// `new_root` is the root after all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullifierTreeBatchUpdate {
    pub tree: Pubkey,
    pub new_root: [u8; 32],
    pub zkp_batch_size: u64,
    pub num_update: u32,
    /// The tree's sequence number after this event, taken from the chain rather
    /// than counted locally.
    ///
    /// This is load-bearing: the API serves `root_seq % root_history_capacity`
    /// as the root index a client must quote, and on chain that index is a ring
    /// pointer advanced once per *applied zkp batch*. Counting events instead of
    /// batches drifts by one per cascade, and a client then proves against one
    /// root while the program checks another -- every transfer fails proof
    /// verification. Taking the number from the event keeps the two in step and
    /// repairs any existing drift on the next update.
    pub sequence_number: u64,
    pub signature: Signature,
}

impl NullifierTreeBatchUpdate {
    /// Nullifiers appended by this event across all of its zkp batches.
    pub fn appended_count(&self) -> u64 {
        self.zkp_batch_size * u64::from(self.num_update)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingsTransactionUpdate {
    pub signature: Signature,
    pub event_index: i16,
    pub slot: u64,
    /// The ring's `ring_auth` PDA; `None` when no ring authorized this.
    pub ring_config: Option<[u8; 32]>,
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

/// A ring registering itself with the pool. `program_id` is written once at
/// creation and never updated, so these rows are append-only and the
/// `ring_config` -> `program_id` mapping is stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingConfigUpdate {
    /// The ring's `ring_auth` PDA, which is also the config account.
    pub ring_config: [u8; 32],
    pub program_id: [u8; 32],
    pub authority: [u8; 32],
    pub slot: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct StateUpdate {
    pub transactions: HashSet<Transaction>,
    pub rings_transactions: Vec<RingsTransactionUpdate>,
    pub ring_configs: Vec<RingConfigUpdate>,
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
            merged.ring_configs.extend(update.ring_configs);
            merged
                .nullifier_tree_batch_updates
                .extend(update.nullifier_tree_batch_updates);
        }

        merged
    }
}
