use rings_tree::{InitAddressTreeAccountsInstructionData, TreeAccount};

pub const STATE_HEIGHT: usize = 32;

// Production batched-address-tree parameters. The bloom filter size and hash
// count are now compile-time const generics of the tree layout.
pub const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE: u64 = 30_000;
pub const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 250;
pub const ADDRESS_TREE_HEIGHT: u32 = 40;
pub const ADDRESS_TREE_ROOT_HISTORY_CAPACITY: u32 = 120;

/// Canonical nullifier (batched address) tree parameters for the shielded pool.
pub fn address_tree_params() -> InitAddressTreeAccountsInstructionData {
    InitAddressTreeAccountsInstructionData {
        index: 0,
        program_owner: None,
        forester: None,
        input_queue_batch_size: ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        input_queue_zkp_batch_size: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        height: ADDRESS_TREE_HEIGHT,
        root_history_capacity: ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
        network_fee: None,
        rollover_threshold: None,
        close_threshold: None,
    }
}

/// Total tree-account byte length. Delegates to the canonical `rings-tree`
/// layout so the account allocator and `TreeAccount::init` agree exactly.
pub fn tree_account_size() -> usize {
    TreeAccount::account_size()
}

/// Byte offset of the state (utxo) tree's current root within the account.
pub fn state_root_offset() -> usize {
    TreeAccount::state_root_offset()
}
