pub mod config;
pub mod discriminator;
#[cfg(feature = "state-tree")]
pub mod tree;

pub use config::{ProtocolConfig, ZoneConfig, PROTOCOL_CONFIG_MAX_MERGE_AUTHORITIES};
#[cfg(feature = "state-tree")]
pub use tree::{
    address_tree_params, state_root_offset, tree_account_size, ADDRESS_TREE_BLOOM_FILTER_CAPACITY,
    ADDRESS_TREE_BLOOM_FILTER_NUM_ITERS, ADDRESS_TREE_HEIGHT, ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
    ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE, ADDRESS_TREE_ROOT_HISTORY_CAPACITY, STATE_HEIGHT,
};
