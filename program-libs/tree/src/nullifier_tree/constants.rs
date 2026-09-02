pub const DEFAULT_NULLIFIER_TREE_HEIGHT: u32 = 40;

pub const DEFAULT_NULLIFIER_BATCH_SIZE: u64 = 25000;

pub const DEFAULT_NULLIFIER_ZKP_BATCH_SIZE: u64 = 250;

/// Root of a height-40 indexed Merkle tree holding the single leaf
/// `H(0, p-1)`, where `p-1` is the BN254 sentinel. Derived from
/// `zolana-merkle-tree` in `tests/nullifier_tree/init_roots.rs`.
pub const NULLIFIER_TREE_INIT_ROOT_40: [u8; 32] = [
    29, 142, 113, 166, 1, 179, 232, 222, 187, 186, 155, 85, 123, 131, 105, 199, 244, 4, 174, 87,
    190, 191, 8, 82, 35, 107, 7, 40, 32, 149, 66, 119,
];

pub const NUM_BATCHES: usize = 2;

pub const NULLIFIER_TREE_ZKP_BATCHES: usize =
    (DEFAULT_NULLIFIER_BATCH_SIZE / DEFAULT_NULLIFIER_ZKP_BATCH_SIZE) as usize;
