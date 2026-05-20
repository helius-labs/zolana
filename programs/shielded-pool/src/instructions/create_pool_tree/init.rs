//! Combined-account pool-tree layout + init.
//!
//! One Solana account hosts both:
//! - an **address sub-tree** (batched address merkle tree, `BatchedMerkleTreeAccount`)
//! - a **state sub-tree** (append-only sparse merkle, `SparseMerkleTree<Poseidon, HEIGHT>`)
//!
//! Address sub-tree is placed first so its zero-copy reads land at an
//! 8-byte-aligned offset (offset 8, immediately after the 8-byte
//! combined-account discriminator). State sub-tree follows.
//!
//! Byte layout:
//!
//! ```text
//! offset                size                          field
//! --------------------  ----------------------------  ------------------------------
//! 0                     8                             combined discriminator (u64 LE)
//! 8                     address_sub_tree_size()       address sub-tree (BatchedMerkleTreeAccount)
//! STATE_OFFSET          8                             state sub-tree next_index (u64 LE)
//! STATE_OFFSET + 8      32                            state sub-tree current root
//! STATE_OFFSET + 40     HEIGHT * 32 = 832             state sub-tree subtrees
//! ```
//!
//! The combined discriminator is a single byte stored as u64 LE; the high bits
//! are zero so it's transparent to both `discriminator[0]`-style reads and
//! 8-byte-aligned reads.

use light_batched_merkle_tree::{
    initialize_address_tree::{
        init_batched_address_merkle_tree_account, InitAddressTreeAccountsInstructionData,
    },
    merkle_tree::get_merkle_tree_account_size,
};
use light_hasher::Poseidon;
use light_sparse_merkle_tree::SparseMerkleTree;
use pinocchio::Address;
use zolana_interface::state::discriminator::POOL_TREE_HEADER;

pub const STATE_HEIGHT: usize = 26;

pub const DISCRIMINATOR_LEN: usize = 8;
pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const ADDRESS_SUB_TREE_OFFSET: usize = DISCRIMINATOR_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolTreeError {
    BufferTooSmall,
    InvalidDiscriminator,
    StateAppendFailed,
    AddressInitFailed,
}

pub fn address_tree_params() -> InitAddressTreeAccountsInstructionData {
    InitAddressTreeAccountsInstructionData {
        rollover_threshold: None,
        network_fee: None,
        forester: None,
        program_owner: None,
        ..Default::default()
    }
}

pub fn address_sub_tree_size() -> usize {
    let p = address_tree_params();
    get_merkle_tree_account_size(
        p.input_queue_batch_size,
        p.bloom_filter_capacity,
        p.input_queue_zkp_batch_size,
        p.root_history_capacity,
        p.height,
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

pub fn pool_tree_account_size() -> usize {
    state_subtrees_offset() + STATE_HEIGHT * 32
}

pub fn pool_tree_discriminator() -> u8 {
    POOL_TREE_HEADER
}

fn write_discriminator(bytes: &mut [u8]) {
    let value = pool_tree_discriminator() as u64;
    bytes[DISCRIMINATOR_OFFSET..DISCRIMINATOR_OFFSET + 8].copy_from_slice(&value.to_le_bytes());
}

fn check_discriminator(bytes: &[u8]) -> Result<(), PoolTreeError> {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[DISCRIMINATOR_OFFSET..DISCRIMINATOR_OFFSET + 8]);
    if u64::from_le_bytes(buf) != pool_tree_discriminator() as u64 {
        return Err(PoolTreeError::InvalidDiscriminator);
    }
    Ok(())
}

pub fn init_pool_tree_account(
    bytes: &mut [u8],
    owner: &Address,
    tree_pubkey: &Address,
) -> Result<(), PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    write_discriminator(bytes);

    let (head, state) = bytes.split_at_mut(state_sub_tree_offset());
    let address = &mut head[ADDRESS_SUB_TREE_OFFSET..];

    init_batched_address_merkle_tree_account(
        *owner,
        address_tree_params(),
        address,
        0,
        *tree_pubkey,
    )
    .map(|_| ())
    .map_err(|_| PoolTreeError::AddressInitFailed)?;

    init_state_sub_tree(state);
    Ok(())
}

fn init_state_sub_tree(state: &mut [u8]) {
    // `state` starts at state_sub_tree_offset() within the combined account.
    // Offsets below are relative to `state`.
    state[0..8].copy_from_slice(&0u64.to_le_bytes());
    let smt = SparseMerkleTree::<Poseidon, STATE_HEIGHT>::new_empty();
    state[8..40].copy_from_slice(&smt.root());
    write_subtrees_to(state, 40, &smt.get_subtrees());
}

pub fn append_state_leaves(
    bytes: &mut [u8],
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;

    let next_index = read_state_next_index(bytes);
    let subtrees = read_state_subtrees(bytes);

    let mut smt = SparseMerkleTree::<Poseidon, STATE_HEIGHT>::new(subtrees, next_index);
    let mut new_root = [0u8; 32];
    for leaf in leaves {
        smt.append(*leaf);
        new_root = smt.root();
    }

    write_state_next_index(bytes, smt.get_next_index() as u64);
    let root_offset = state_root_offset();
    bytes[root_offset..root_offset + 32].copy_from_slice(&new_root);
    write_state_subtrees(bytes, &smt.get_subtrees());

    Ok(new_root)
}

pub fn address_sub_tree_slice_mut(bytes: &mut [u8]) -> Result<&mut [u8], PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(&mut bytes[ADDRESS_SUB_TREE_OFFSET..state_sub_tree_offset()])
}

#[inline]
pub fn read_state_next_index(bytes: &[u8]) -> usize {
    let offset = state_next_index_offset();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(buf) as usize
}

#[inline]
fn write_state_next_index(bytes: &mut [u8], value: u64) {
    let offset = state_next_index_offset();
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn read_state_subtrees(bytes: &[u8]) -> [[u8; 32]; STATE_HEIGHT] {
    let mut subtrees = [[0u8; 32]; STATE_HEIGHT];
    let base = state_subtrees_offset();
    for (i, dst) in subtrees.iter_mut().enumerate() {
        let start = base + i * 32;
        dst.copy_from_slice(&bytes[start..start + 32]);
    }
    subtrees
}

#[inline]
fn write_state_subtrees(bytes: &mut [u8], subtrees: &[[u8; 32]; STATE_HEIGHT]) {
    let base = state_subtrees_offset();
    for (i, src) in subtrees.iter().enumerate() {
        let start = base + i * 32;
        bytes[start..start + 32].copy_from_slice(src);
    }
}

#[inline]
fn write_subtrees_to(
    state: &mut [u8],
    subtrees_offset: usize,
    subtrees: &[[u8; 32]; STATE_HEIGHT],
) {
    for (i, src) in subtrees.iter().enumerate() {
        let start = subtrees_offset + i * 32;
        state[start..start + 32].copy_from_slice(src);
    }
}
