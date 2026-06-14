pub const STATE_HEIGHT: usize = 26;
pub const STATE_ROOT_HISTORY_CAPACITY: usize = 200;

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

pub const DISCRIMINATOR_LEN: usize = 8;
pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const PAUSED_FLAG: u8 = 1;
pub const FLAGS_LEN: usize = 1;
pub const ADDRESS_SUB_TREE_OFFSET: usize = DISCRIMINATOR_LEN;
pub const ADDRESS_SUB_TREE_SIZE: usize = 1_163_024;

pub const fn address_sub_tree_size() -> usize {
    ADDRESS_SUB_TREE_SIZE
}

pub const fn state_sub_tree_offset() -> usize {
    ADDRESS_SUB_TREE_OFFSET + address_sub_tree_size()
}

pub const fn state_next_index_offset() -> usize {
    state_sub_tree_offset()
}

pub const fn state_root_offset() -> usize {
    state_sub_tree_offset() + 8
}

pub const fn state_subtrees_offset() -> usize {
    state_sub_tree_offset() + 8 + 32
}

pub const fn state_root_history_meta_offset() -> usize {
    state_subtrees_offset() + STATE_HEIGHT * 32
}

pub const fn state_root_history_offset() -> usize {
    state_root_history_meta_offset() + 4
}

pub const fn tree_flags_offset() -> usize {
    state_root_history_offset() + STATE_ROOT_HISTORY_CAPACITY * 32
}

pub const fn tree_account_size() -> usize {
    tree_flags_offset() + FLAGS_LEN
}
