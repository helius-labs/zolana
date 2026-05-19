//! Static configuration and account-init helper for shielded-pool state trees.
//!
//! State trees are append-only `ConcurrentMerkleTree<Poseidon, HEIGHT>` accounts.
//! HEIGHT is fixed at 26 (matches the upstream Light Protocol state-tree depth
//! and gives ~67M leaves capacity). The caller must allocate the account at
//! exactly [`state_tree_size`] bytes before issuing `create_state_tree`.

use light_concurrent_merkle_tree::{
    errors::ConcurrentMerkleTreeError, zero_copy::ConcurrentMerkleTreeZeroCopyMut,
    ConcurrentMerkleTree,
};
use light_hasher::Poseidon;

pub const HEIGHT: usize = 26;
pub const CHANGELOG_CAPACITY: usize = 64;
pub const ROOTS_CAPACITY: usize = 2400;

/// Bytes required for a state-tree account at the given canopy depth.
pub fn state_tree_size(canopy_depth: usize) -> usize {
    ConcurrentMerkleTree::<Poseidon, HEIGHT>::size_in_account(
        HEIGHT,
        CHANGELOG_CAPACITY,
        ROOTS_CAPACITY,
        canopy_depth,
    )
}

/// Initialize the state-tree fields in-place into a freshly-allocated account
/// buffer. Returns an error if `bytes` is too small.
pub fn init_state_tree_account(
    bytes: &mut [u8],
    canopy_depth: usize,
) -> Result<(), ConcurrentMerkleTreeError> {
    let mut tree =
        ConcurrentMerkleTreeZeroCopyMut::<Poseidon, HEIGHT>::from_bytes_zero_copy_init(
            bytes,
            HEIGHT,
            canopy_depth,
            CHANGELOG_CAPACITY,
            ROOTS_CAPACITY,
        )?;
    tree.init()
}
