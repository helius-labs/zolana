// This file stores constants which do not have to be configured.

pub const DEFAULT_BATCH_ADDRESS_TREE_HEIGHT: u32 = 40;

pub const DEFAULT_BATCH_ROOT_HISTORY_LEN: u32 = 200;

pub const DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN: u32 = 120;

pub const DEFAULT_NUM_BATCHES: u64 = 2;

pub const TEST_DEFAULT_BATCH_SIZE: u64 = 50;

pub const TEST_DEFAULT_ZKP_BATCH_SIZE: u64 = 10;

pub const DEFAULT_ADDRESS_BATCH_SIZE: u64 = 30000;

pub const DEFAULT_ADDRESS_ZKP_BATCH_SIZE: u64 = 250;

// False positive probability 1.0E-12 for 30k elements.
pub const ADDRESS_BLOOM_FILTER_CAPACITY: u64 = 4_603_072;
pub const ADDRESS_BLOOM_FILTER_NUM_HASHES: u64 = 10;

pub const ADDRESS_TREE_INIT_ROOT_40: [u8; 32] = [
    28, 65, 107, 255, 208, 234, 51, 3, 131, 95, 62, 130, 202, 177, 176, 26, 216, 81, 64, 184, 200,
    25, 95, 124, 248, 129, 44, 109, 229, 146, 106, 76,
];

/// Init root of a height-40 indexed Merkle tree seeded with the BN254 `p-1`
/// sentinel (the highest valid field element). Used to initialize nullifier
/// trees, whose values are full BN254 field elements rather than 248-bit
/// addresses. Generated from `rings-merkle-tree`; see
/// `tests/init_roots.rs`.
pub const NULLIFIER_TREE_INIT_ROOT_40: [u8; 32] = [
    29, 142, 113, 166, 1, 179, 232, 222, 187, 186, 155, 85, 123, 131, 105, 199, 244, 4, 174, 87,
    190, 191, 8, 82, 35, 107, 7, 40, 32, 149, 66, 119,
];

pub const NUM_BATCHES: usize = 2;

pub const ADDRESS_TREE_DEFAULT_NUM_ITERS: usize = ADDRESS_BLOOM_FILTER_NUM_HASHES as usize;

pub const ADDRESS_TREE_DEFAULT_RH: usize = DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN as usize;
pub const ADDRESS_TREE_DEFAULT_BLOOM: usize = (ADDRESS_BLOOM_FILTER_CAPACITY / 8) as usize;
pub const ADDRESS_TREE_DEFAULT_ZKP: usize =
    (DEFAULT_ADDRESS_BATCH_SIZE / DEFAULT_ADDRESS_ZKP_BATCH_SIZE) as usize;
