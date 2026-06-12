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
//! Regions, in order (offsets are computed by the helpers below):
//!
//! - combined discriminator: 8 bytes (u64 LE)
//! - address sub-tree: `address_sub_tree_size()` bytes
//! - state sub-tree: next_index (8), current root (32), subtrees
//!   (`STATE_HEIGHT * 32`), root-history meta (4) + root history
//!   (`STATE_ROOT_HISTORY_CAPACITY * 32`)
//! - flags: 1 byte (bit 0 = paused), at `tree_flags_offset()`
//!
//! The nullifier tree keeps no separate region: it IS the address sub-tree, and
//! its own root_history is the nullifier-root cache.
//!
//! The flags byte is the LAST region, outside the discriminator word: storing it
//! at byte 1 (inside bytes[0..8]) would corrupt a u64-LE read of the
//! discriminator once paused. The combined discriminator is a single byte stored
//! as u64 LE; its high bits stay zero so it reads identically as `bytes[0]` and
//! as an 8-byte-aligned u64.

use light_batched_merkle_tree::{
    initialize_address_tree::{
        init_batched_address_merkle_tree_account, InitAddressTreeAccountsInstructionData,
    },
    merkle_tree::get_merkle_tree_account_size,
};
use light_hasher::Poseidon;
use light_sparse_merkle_tree::SparseMerkleTree;
use pinocchio::Address;
use zolana_interface::state::discriminator::TREE_HEADER;

pub const STATE_HEIGHT: usize = 26;
pub const STATE_ROOT_HISTORY_CAPACITY: usize = 200;

pub const DISCRIMINATOR_LEN: usize = 8;
pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const PAUSED_FLAG: u8 = 1;
pub const FLAGS_LEN: usize = 1;
pub const ADDRESS_SUB_TREE_OFFSET: usize = DISCRIMINATOR_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    BufferTooSmall,
    InvalidDiscriminator,
    StateAppendFailed,
    AddressInitFailed,
    InvalidRootIndex,
}

pub fn address_tree_params() -> InitAddressTreeAccountsInstructionData {
    InitAddressTreeAccountsInstructionData {
        index: 0,
        program_owner: None,
        forester: None,
        bloom_filter_num_iters: 3,
        input_queue_batch_size: 10,
        input_queue_zkp_batch_size: 10,
        height: 40,
        root_history_capacity: 200,
        bloom_filter_capacity: 20_000 * 8,
        network_fee: None,
        rollover_threshold: None,
        close_threshold: None,
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

pub fn state_root_history_meta_offset() -> usize {
    state_subtrees_offset() + STATE_HEIGHT * 32
}

pub fn state_root_history_offset() -> usize {
    state_root_history_meta_offset() + 4
}

// The nullifier tree keeps no SPP-side state here: it IS the Light batched
// address tree in the address sub-tree, whose own root_history is the
// nullifier-root cache referenced by transact's nullifier_tree_root_index.

/// Offset of the 1-byte flags region (bit 0 = paused). It lives at the END of
/// the account, OUTSIDE the discriminator word, so toggling paused never
/// corrupts a u64-LE read of the combined discriminator.
pub fn tree_flags_offset() -> usize {
    state_root_history_offset() + STATE_ROOT_HISTORY_CAPACITY * 32
}

pub fn tree_account_size() -> usize {
    tree_flags_offset() + FLAGS_LEN
}

pub fn tree_discriminator() -> u8 {
    TREE_HEADER
}

fn write_discriminator(bytes: &mut [u8]) {
    let value = tree_discriminator() as u64;
    bytes[DISCRIMINATOR_OFFSET..DISCRIMINATOR_OFFSET + 8].copy_from_slice(&value.to_le_bytes());
}

fn check_discriminator(bytes: &[u8]) -> Result<(), TreeError> {
    if bytes[DISCRIMINATOR_OFFSET] != tree_discriminator() {
        return Err(TreeError::InvalidDiscriminator);
    }
    Ok(())
}

pub fn init_tree_account(
    bytes: &mut [u8],
    owner: &Address,
    tree_pubkey: &Address,
) -> Result<(), TreeError> {
    if bytes.len() < tree_account_size() {
        return Err(TreeError::BufferTooSmall);
    }
    // Refuse to re-initialize: a fresh account is zeroed, so a non-zero
    // discriminator means the tree already exists (mirrors create_spl_interface's
    // zeroed-check). Without this a second create_tree would clobber a live
    // tree's roots and subtrees.
    if bytes[DISCRIMINATOR_OFFSET..DISCRIMINATOR_OFFSET + DISCRIMINATOR_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(TreeError::InvalidDiscriminator);
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
    .map_err(|_| TreeError::AddressInitFailed)?;

    init_state_sub_tree(state);
    Ok(())
}

fn init_state_sub_tree(state: &mut [u8]) {
    // `state` starts at state_sub_tree_offset() within the combined account.
    // Offsets below are relative to `state`.
    state[0..8].copy_from_slice(&0u64.to_le_bytes());
    let smt = SparseMerkleTree::<Poseidon, STATE_HEIGHT>::new_empty();
    let root = smt.root();
    state[8..40].copy_from_slice(&root);
    write_subtrees_to(state, 40, &smt.get_subtrees());
    state[state_root_history_meta_relative_offset()..state_root_history_meta_relative_offset() + 2]
        .copy_from_slice(&0u16.to_le_bytes());
    state[state_root_history_meta_relative_offset() + 2
        ..state_root_history_meta_relative_offset() + 4]
        .copy_from_slice(&1u16.to_le_bytes());
    let history = state_root_history_relative_offset();
    state[history..history + 32].copy_from_slice(&root);
}

pub fn append_state_leaves(
    bytes: &mut [u8],
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], TreeError> {
    if bytes.len() < tree_account_size() {
        return Err(TreeError::BufferTooSmall);
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
    push_state_root(bytes, new_root);

    Ok(new_root)
}

pub fn state_root_by_index(bytes: &[u8], index: u16) -> Result<[u8; 32], TreeError> {
    if bytes.len() < tree_account_size() {
        return Err(TreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;

    root_history_value_by_index(
        bytes,
        state_root_history_offset(),
        STATE_ROOT_HISTORY_CAPACITY,
        read_state_root_history_meta(bytes),
        index,
    )
}

pub fn current_state_root_index(bytes: &[u8]) -> Result<u16, TreeError> {
    if bytes.len() < tree_account_size() {
        return Err(TreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(read_state_root_history_meta(bytes).0)
}

pub fn is_tree_paused(bytes: &[u8]) -> Result<bool, TreeError> {
    if bytes.len() < tree_account_size() {
        return Err(TreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(bytes[tree_flags_offset()] & PAUSED_FLAG != 0)
}

pub fn set_tree_paused(bytes: &mut [u8], paused: bool) -> Result<(), TreeError> {
    if bytes.len() < tree_account_size() {
        return Err(TreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    let flags_offset = tree_flags_offset();
    if paused {
        bytes[flags_offset] |= PAUSED_FLAG;
    } else {
        bytes[flags_offset] &= !PAUSED_FLAG;
    }
    Ok(())
}

pub fn address_sub_tree_slice_mut(bytes: &mut [u8]) -> Result<&mut [u8], TreeError> {
    if bytes.len() < tree_account_size() {
        return Err(TreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(&mut bytes[ADDRESS_SUB_TREE_OFFSET..state_sub_tree_offset()])
}

#[inline]
fn read_state_next_index(bytes: &[u8]) -> usize {
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
fn read_state_root_history_meta(bytes: &[u8]) -> (u16, u16) {
    let offset = state_root_history_meta_offset();
    let mut cursor = [0u8; 2];
    let mut len = [0u8; 2];
    cursor.copy_from_slice(&bytes[offset..offset + 2]);
    len.copy_from_slice(&bytes[offset + 2..offset + 4]);
    (u16::from_le_bytes(cursor), u16::from_le_bytes(len))
}

#[inline]
fn write_state_root_history_meta(bytes: &mut [u8], cursor: u16, len: u16) {
    let offset = state_root_history_meta_offset();
    bytes[offset..offset + 2].copy_from_slice(&cursor.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&len.to_le_bytes());
}

fn root_history_value_by_index(
    bytes: &[u8],
    base_offset: usize,
    capacity: usize,
    meta: (u16, u16),
    index: u16,
) -> Result<[u8; 32], TreeError> {
    let index = index as usize;
    let (cursor, len) = meta;
    let len = len as usize;
    if len == 0 || index >= capacity {
        return Err(TreeError::InvalidRootIndex);
    }
    if len < capacity && index >= len {
        return Err(TreeError::InvalidRootIndex);
    }
    if len == 1 && index != cursor as usize {
        return Err(TreeError::InvalidRootIndex);
    }

    let base = base_offset + index * 32;
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[base..base + 32]);
    if root.iter().all(|byte| *byte == 0) {
        return Err(TreeError::InvalidRootIndex);
    }
    Ok(root)
}

#[inline]
fn push_state_root(bytes: &mut [u8], root: [u8; 32]) {
    let (cursor, len) = read_state_root_history_meta(bytes);
    let next = (usize::from(cursor) + 1) % STATE_ROOT_HISTORY_CAPACITY;
    let next_len = (usize::from(len) + 1).min(STATE_ROOT_HISTORY_CAPACITY) as u16;
    let base = state_root_history_offset() + next * 32;
    bytes[base..base + 32].copy_from_slice(&root);
    write_state_root_history_meta(bytes, next as u16, next_len);
}

#[inline]
fn state_root_history_meta_relative_offset() -> usize {
    state_root_history_meta_offset() - state_sub_tree_offset()
}

#[inline]
fn state_root_history_relative_offset() -> usize {
    state_root_history_offset() - state_sub_tree_offset()
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
