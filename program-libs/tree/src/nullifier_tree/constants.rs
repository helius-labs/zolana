pub const DEFAULT_NULLIFIER_TREE_HEIGHT: u32 = 40;

pub const DEFAULT_NULLIFIER_BATCH_SIZE: u64 = 25000;

pub const DEFAULT_NULLIFIER_ZKP_BATCH_SIZE: u64 = 250;

/// Root of a height-40 indexed Merkle tree holding the single leaf
/// `H(0, p-1)`, where `p-1` is the BN254 sentinel and `H` the Poseidon2 tree
/// hash. Checked against `zolana-merkle-tree` and `test-vectors/tree_hash.json`
/// in `tests/nullifier_tree/init_roots.rs`.
pub const NULLIFIER_TREE_INIT_ROOT_40: [u8; 32] = [
    18, 50, 102, 236, 232, 203, 236, 254, 188, 110, 212, 141, 99, 49, 190, 35, 206, 186, 231, 88,
    75, 195, 7, 50, 50, 99, 189, 215, 185, 37, 38, 21,
];

pub const NUM_BATCHES: usize = 2;

pub const NULLIFIER_TREE_ZKP_BATCHES: usize =
    (DEFAULT_NULLIFIER_BATCH_SIZE / DEFAULT_NULLIFIER_ZKP_BATCH_SIZE) as usize;
