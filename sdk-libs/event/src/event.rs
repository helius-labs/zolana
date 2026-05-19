use borsh::{BorshDeserialize, BorshSerialize};

/// Emitted by `create_pool_tree` after the account is initialized.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct PoolTreeCreatedEvent {
    pub pool_tree: [u8; 32],
    pub owner: [u8; 32],
    pub initial_state_root: [u8; 32],
}

/// Emitted by `append_state_leaves` after each batch.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct StateLeavesAppendedEvent {
    pub pool_tree: [u8; 32],
    pub start_index: u64,
    pub new_root: [u8; 32],
    pub leaves: Vec<[u8; 32]>,
}

/// Emitted by `insert_addresses` for each address pushed into the in-account
/// input queue.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct AddressQueuedEvent {
    pub pool_tree: [u8; 32],
    pub address: [u8; 32],
    pub slot: u64,
    pub queue_next_index: u64,
}

/// Emitted by `batch_update_address_tree` after the Groth16 proof verifies
/// and the new root is appended to root history.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct AddressTreeBatchUpdatedEvent {
    pub pool_tree: [u8; 32],
    pub new_root: [u8; 32],
    pub root_index: u32,
    pub sequence_number: u64,
}

/// Discriminator-tagged enum spanning all shielded-pool events. Indexers can
/// match on the leading byte to dispatch parsing.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum ShieldedPoolEvent {
    PoolTreeCreated(PoolTreeCreatedEvent),
    StateLeavesAppended(StateLeavesAppendedEvent),
    AddressQueued(AddressQueuedEvent),
    AddressTreeBatchUpdated(AddressTreeBatchUpdatedEvent),
}
