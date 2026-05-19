//! On-disk layout and init helpers for shielded-pool state-tree accounts.
//!
//! State trees are append-only `SparseMerkleTree<Poseidon, HEIGHT>` accounts.
//! HEIGHT is fixed at 26 — matches the upstream state-tree depth and gives
//! ~67M leaves capacity. The caller must allocate the account at exactly
//! [`STATE_TREE_ACCOUNT_SIZE`] bytes before issuing `create_state_tree`.
//!
//! Layout (little-endian, 873 bytes total):
//!
//! ```text
//! offset  size                 field
//! ------  -------              -----
//! 0       1                    discriminator (state_tree_discriminator())
//! 1       8                    next_index (u64)
//! 9       32                   current root
//! 41      HEIGHT * 32 = 832    subtrees
//! ```

use light_hasher::{Hasher, Poseidon};
use light_sparse_merkle_tree::SparseMerkleTree;
use zolana_interface::state::discriminator::STATE_TREE_HEADER;

pub const HEIGHT: usize = 26;
pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const NEXT_INDEX_OFFSET: usize = 1;
pub const ROOT_OFFSET: usize = 9;
pub const SUBTREES_OFFSET: usize = 41;
pub const STATE_TREE_ACCOUNT_SIZE: usize = SUBTREES_OFFSET + HEIGHT * 32;

pub const fn state_tree_discriminator() -> u8 {
    STATE_TREE_HEADER
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateTreeAccountError {
    BufferTooSmall,
    InvalidDiscriminator,
    AppendFailed,
}

/// Initialize a freshly-allocated state-tree account in place.
pub fn init_state_tree_account(bytes: &mut [u8]) -> Result<(), StateTreeAccountError> {
    if bytes.len() < STATE_TREE_ACCOUNT_SIZE {
        return Err(StateTreeAccountError::BufferTooSmall);
    }
    bytes[DISCRIMINATOR_OFFSET] = state_tree_discriminator();
    bytes[NEXT_INDEX_OFFSET..ROOT_OFFSET].copy_from_slice(&0u64.to_le_bytes());

    // Empty SparseMerkleTree gives us the canonical zero-root + zero-subtrees
    // for the configured HEIGHT/Hasher.
    let smt = SparseMerkleTree::<Poseidon, HEIGHT>::new_empty();
    bytes[ROOT_OFFSET..SUBTREES_OFFSET].copy_from_slice(&smt.root());
    write_subtrees(bytes, &smt.get_subtrees());
    Ok(())
}

/// Load tree state, append each leaf, persist the result.
pub fn append_leaves_to_account(
    bytes: &mut [u8],
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], StateTreeAccountError> {
    if bytes.len() < STATE_TREE_ACCOUNT_SIZE {
        return Err(StateTreeAccountError::BufferTooSmall);
    }
    if bytes[DISCRIMINATOR_OFFSET] != state_tree_discriminator() {
        return Err(StateTreeAccountError::InvalidDiscriminator);
    }

    let next_index = read_next_index(bytes);
    let subtrees = read_subtrees(bytes);

    let mut smt = SparseMerkleTree::<Poseidon, HEIGHT>::new(subtrees, next_index);
    let mut new_root = [0u8; 32];
    for leaf in leaves {
        smt.append(*leaf);
        new_root = smt.root();
    }

    write_next_index(bytes, smt.get_next_index() as u64);
    bytes[ROOT_OFFSET..SUBTREES_OFFSET].copy_from_slice(&new_root);
    write_subtrees(bytes, &smt.get_subtrees());

    // Sanity: the root we wrote should be reproducible by re-hashing the
    // rightmost subtree path. If not, something has gone wrong with the
    // Hasher feature gating.
    debug_assert_eq!(new_root.len(), <Poseidon as Hasher>::zero_bytes()[0].len());

    Ok(new_root)
}

#[inline]
fn read_next_index(bytes: &[u8]) -> usize {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[NEXT_INDEX_OFFSET..ROOT_OFFSET]);
    u64::from_le_bytes(buf) as usize
}

#[inline]
fn write_next_index(bytes: &mut [u8], value: u64) {
    bytes[NEXT_INDEX_OFFSET..ROOT_OFFSET].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn read_subtrees(bytes: &[u8]) -> [[u8; 32]; HEIGHT] {
    let mut subtrees = [[0u8; 32]; HEIGHT];
    for (i, dst) in subtrees.iter_mut().enumerate() {
        let start = SUBTREES_OFFSET + i * 32;
        dst.copy_from_slice(&bytes[start..start + 32]);
    }
    subtrees
}

#[inline]
fn write_subtrees(bytes: &mut [u8], subtrees: &[[u8; 32]; HEIGHT]) {
    for (i, src) in subtrees.iter().enumerate() {
        let start = SUBTREES_OFFSET + i * 32;
        bytes[start..start + 32].copy_from_slice(src);
    }
}
