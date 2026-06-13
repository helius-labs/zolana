use light_batched_merkle_tree::merkle_tree::get_merkle_tree_account_size;

pub const STATE_HEIGHT: usize = 26;
pub const STATE_ROOT_HISTORY_CAPACITY: usize = 200;

pub const ADDRESS_TREE_BLOOM_FILTER_NUM_ITERS: u64 = 3;
pub const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE: u64 = 10;
pub const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: u64 = 10;
pub const ADDRESS_TREE_HEIGHT: u32 = 40;
pub const ADDRESS_TREE_ROOT_HISTORY_CAPACITY: u32 = 200;
pub const ADDRESS_TREE_BLOOM_FILTER_CAPACITY: u64 = 20_000 * 8;

pub const DISCRIMINATOR_LEN: usize = 8;
pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const PAUSED_FLAG: u8 = 1;
pub const FLAGS_LEN: usize = 1;
pub const ADDRESS_SUB_TREE_OFFSET: usize = DISCRIMINATOR_LEN;

pub fn address_sub_tree_size() -> usize {
    get_merkle_tree_account_size(
        ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        ADDRESS_TREE_BLOOM_FILTER_CAPACITY,
        ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
        ADDRESS_TREE_HEIGHT,
    )
}

pub fn state_sub_tree_offset() -> usize {
    ADDRESS_SUB_TREE_OFFSET + address_sub_tree_size()
}

pub fn state_next_index_offset() -> usize {
    state_sub_tree_offset()
}

pub fn state_root_offset() -> usize {
    state_sub_tree_offset() + 8
}

pub fn state_subtrees_offset() -> usize {
    state_sub_tree_offset() + 8 + 32
}

pub fn state_root_history_meta_offset() -> usize {
    state_subtrees_offset() + STATE_HEIGHT * 32
}

pub fn state_root_history_offset() -> usize {
    state_root_history_meta_offset() + 4
}

pub fn tree_flags_offset() -> usize {
    state_root_history_offset() + STATE_ROOT_HISTORY_CAPACITY * 32
}

pub fn tree_account_size() -> usize {
    tree_flags_offset() + FLAGS_LEN
}
