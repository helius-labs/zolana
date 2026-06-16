use zolana_tree::{InitAddressTreeAccountsInstructionData, TreeAccount};

pub const STATE_HEIGHT: usize = 26;

// Light Protocol production batched-address-tree parameters (mirror
// `InitAddressTreeAccountsInstructionData::default()` in light-batched-merkle-tree:
// ADDRESS_BLOOM_FILTER_NUM_HASHES, DEFAULT_ADDRESS_BATCH_SIZE,
// DEFAULT_ADDRESS_ZKP_BATCH_SIZE, DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
// DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN, ADDRESS_BLOOM_FILTER_CAPACITY). Toy
// values here make Light's tree init panic while sizing the bloom filters.
pub const ADDRESS_TREE_BLOOM_FILTER_NUM_ITERS: u64 = 10;
pub const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE: u64 = 30_000;
pub const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 250;
pub const ADDRESS_TREE_HEIGHT: u32 = 40;
pub const ADDRESS_TREE_ROOT_HISTORY_CAPACITY: u32 = 120;
pub const ADDRESS_TREE_BLOOM_FILTER_CAPACITY: u64 = 4_603_072;

/// Canonical nullifier (batched address) tree parameters for the shielded pool.
pub fn address_tree_params() -> InitAddressTreeAccountsInstructionData {
    InitAddressTreeAccountsInstructionData {
        index: 0,
        program_owner: None,
        forester: None,
        bloom_filter_num_iters: ADDRESS_TREE_BLOOM_FILTER_NUM_ITERS,
        input_queue_batch_size: ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        input_queue_zkp_batch_size: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        height: ADDRESS_TREE_HEIGHT,
        root_history_capacity: ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
        bloom_filter_capacity: ADDRESS_TREE_BLOOM_FILTER_CAPACITY,
        network_fee: None,
        rollover_threshold: None,
        close_threshold: None,
    }
}

/// Total tree-account byte length. Delegates to the canonical `zolana-tree`
/// layout so the account allocator and `TreeAccount::init` agree exactly.
pub fn tree_account_size() -> usize {
    TreeAccount::account_size(STATE_HEIGHT as u8, address_tree_params())
}

/// Byte offset of the state (utxo) tree's current root within the account.
pub fn state_root_offset() -> usize {
    TreeAccount::state_root_offset()
}
