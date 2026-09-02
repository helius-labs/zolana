pub const DEFAULT_NULLIFIER_TREE_HEIGHT: u32 = 40;

pub const DEFAULT_NULLIFIER_BATCH_SIZE: u64 = 30000;

pub const DEFAULT_NULLIFIER_ZKP_BATCH_SIZE: u64 = 250;

/// Init root of a height-40 indexed Merkle tree seeded with the BN254 `p-1`
/// sentinel (the highest valid field element). Used to initialize nullifier
/// trees, whose values are full BN254 field elements rather than 248-bit
/// addresses. Generated from `zolana-merkle-tree`; see
/// `tests/init_roots.rs`.
pub const NULLIFIER_TREE_INIT_ROOT_40: [u8; 32] = [
    29, 142, 113, 166, 1, 179, 232, 222, 187, 186, 155, 85, 123, 131, 105, 199, 244, 4, 174, 87,
    190, 191, 8, 82, 35, 107, 7, 40, 32, 149, 66, 119,
];

pub const NUM_BATCHES: usize = 2;

pub const NULLIFIER_TREE_ZKP_BATCHES: usize =
    (DEFAULT_NULLIFIER_BATCH_SIZE / DEFAULT_NULLIFIER_ZKP_BATCH_SIZE) as usize;
