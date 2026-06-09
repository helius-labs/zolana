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
//! 1                     1                             flags (bit 0 = paused)
//! 8                     address_sub_tree_size()       address sub-tree (BatchedMerkleTreeAccount)
//! STATE_OFFSET          8                             state sub-tree next_index (u64 LE)
//! STATE_OFFSET + 8      32                            state sub-tree current root
//! STATE_OFFSET + 40     HEIGHT * 32 = 832             state sub-tree subtrees
//! STATE_ROOT_HISTORY    4                             root history cursor + len (u16 LE)
//! STATE_ROOT_HISTORY+4  ROOT_HISTORY_CAPACITY * 32    state root history
//! NULLIFIER_ROOT_HISTORY 4                             root history cursor + len (u16 LE)
//! NULLIFIER_ROOT_HISTORY+4 ROOT_HISTORY_CAPACITY * 32   nullifier indexed-tree root history
//! NULLIFIER_NEXT_INDEX 8                               next indexed-tree insertion index
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
pub const STATE_ROOT_HISTORY_CAPACITY: usize = 200;
pub const NULLIFIER_ROOT_HISTORY_CAPACITY: usize = 200;
pub const INITIAL_NULLIFIER_ROOT: [u8; 32] = [
    0x1d, 0x8e, 0x71, 0xa6, 0x01, 0xb3, 0xe8, 0xde, 0xbb, 0xba, 0x9b, 0x55, 0x7b, 0x83, 0x69, 0xc7,
    0xf4, 0x04, 0xae, 0x57, 0xbe, 0xbf, 0x08, 0x52, 0x23, 0x6b, 0x07, 0x28, 0x20, 0x95, 0x42, 0x77,
];

pub const DISCRIMINATOR_LEN: usize = 8;
pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const FLAGS_OFFSET: usize = 1;
pub const PAUSED_FLAG: u8 = 1;
pub const ADDRESS_SUB_TREE_OFFSET: usize = DISCRIMINATOR_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolTreeError {
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

pub fn nullifier_root_history_meta_offset() -> usize {
    state_root_history_offset() + STATE_ROOT_HISTORY_CAPACITY * 32
}

pub fn nullifier_root_history_offset() -> usize {
    nullifier_root_history_meta_offset() + 4
}

pub fn nullifier_next_index_offset() -> usize {
    nullifier_root_history_offset() + NULLIFIER_ROOT_HISTORY_CAPACITY * 32
}

pub fn pool_tree_account_size() -> usize {
    nullifier_next_index_offset() + 8
}

pub fn pool_tree_discriminator() -> u8 {
    POOL_TREE_HEADER
}

fn write_discriminator(bytes: &mut [u8]) {
    let value = pool_tree_discriminator() as u64;
    bytes[DISCRIMINATOR_OFFSET..DISCRIMINATOR_OFFSET + 8].copy_from_slice(&value.to_le_bytes());
}

fn check_discriminator(bytes: &[u8]) -> Result<(), PoolTreeError> {
    if bytes[DISCRIMINATOR_OFFSET] != pool_tree_discriminator() {
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

    let nullifier_meta = nullifier_root_history_meta_relative_offset();
    state[nullifier_meta..nullifier_meta + 2].copy_from_slice(&0u16.to_le_bytes());
    state[nullifier_meta + 2..nullifier_meta + 4].copy_from_slice(&1u16.to_le_bytes());
    let nullifier_history = nullifier_root_history_relative_offset();
    state[nullifier_history..nullifier_history + 32].copy_from_slice(&INITIAL_NULLIFIER_ROOT);
    let nullifier_next_index = nullifier_next_index_relative_offset();
    state[nullifier_next_index..nullifier_next_index + 8].copy_from_slice(&1u64.to_le_bytes());
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
    push_state_root(bytes, new_root);

    Ok(new_root)
}

pub fn current_state_root(bytes: &[u8]) -> Result<[u8; 32], PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;

    let root_offset = state_root_offset();
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[root_offset..root_offset + 32]);
    Ok(root)
}

pub fn state_root_by_index(bytes: &[u8], index: u16) -> Result<[u8; 32], PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
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

pub fn current_state_root_index(bytes: &[u8]) -> Result<u16, PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(read_state_root_history_meta(bytes).0)
}

pub fn nullifier_root_by_index(bytes: &[u8], index: u16) -> Result<[u8; 32], PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    root_history_value_by_index(
        bytes,
        nullifier_root_history_offset(),
        NULLIFIER_ROOT_HISTORY_CAPACITY,
        read_nullifier_root_history_meta(bytes),
        index,
    )
}

pub fn current_nullifier_root_index(bytes: &[u8]) -> Result<u16, PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(read_nullifier_root_history_meta(bytes).0)
}

pub fn current_nullifier_next_index(bytes: &[u8]) -> Result<u64, PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(read_nullifier_next_index(bytes))
}

pub fn push_nullifier_root(bytes: &mut [u8], root: [u8; 32]) -> Result<(), PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    if root.iter().all(|byte| *byte == 0) {
        return Err(PoolTreeError::InvalidRootIndex);
    }

    let (cursor, len) = read_nullifier_root_history_meta(bytes);
    let next = (usize::from(cursor) + 1) % NULLIFIER_ROOT_HISTORY_CAPACITY;
    let next_len = (usize::from(len) + 1).min(NULLIFIER_ROOT_HISTORY_CAPACITY) as u16;
    let base = nullifier_root_history_offset() + next * 32;
    bytes[base..base + 32].copy_from_slice(&root);
    write_nullifier_root_history_meta(bytes, next as u16, next_len);
    Ok(())
}

pub fn push_nullifier_root_with_next_index(
    bytes: &mut [u8],
    root: [u8; 32],
    next_index: u64,
) -> Result<(), PoolTreeError> {
    push_nullifier_root(bytes, root)?;
    write_nullifier_next_index(bytes, next_index);
    Ok(())
}

pub fn is_pool_tree_paused(bytes: &[u8]) -> Result<bool, PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    Ok(bytes[FLAGS_OFFSET] & PAUSED_FLAG != 0)
}

pub fn set_pool_tree_paused(bytes: &mut [u8], paused: bool) -> Result<(), PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
    }
    check_discriminator(bytes)?;
    if paused {
        bytes[FLAGS_OFFSET] |= PAUSED_FLAG;
    } else {
        bytes[FLAGS_OFFSET] &= !PAUSED_FLAG;
    }
    Ok(())
}

pub fn address_sub_tree_slice_mut(bytes: &mut [u8]) -> Result<&mut [u8], PoolTreeError> {
    if bytes.len() < pool_tree_account_size() {
        return Err(PoolTreeError::BufferTooSmall);
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
fn read_nullifier_root_history_meta(bytes: &[u8]) -> (u16, u16) {
    let offset = nullifier_root_history_meta_offset();
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

#[inline]
fn write_nullifier_root_history_meta(bytes: &mut [u8], cursor: u16, len: u16) {
    let offset = nullifier_root_history_meta_offset();
    bytes[offset..offset + 2].copy_from_slice(&cursor.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&len.to_le_bytes());
}

#[inline]
fn read_nullifier_next_index(bytes: &[u8]) -> u64 {
    let offset = nullifier_next_index_offset();
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[inline]
fn write_nullifier_next_index(bytes: &mut [u8], next_index: u64) {
    let offset = nullifier_next_index_offset();
    bytes[offset..offset + 8].copy_from_slice(&next_index.to_le_bytes());
}

fn root_history_value_by_index(
    bytes: &[u8],
    base_offset: usize,
    capacity: usize,
    meta: (u16, u16),
    index: u16,
) -> Result<[u8; 32], PoolTreeError> {
    let index = index as usize;
    let (cursor, len) = meta;
    let len = len as usize;
    if len == 0 || index >= capacity {
        return Err(PoolTreeError::InvalidRootIndex);
    }
    if len < capacity && index >= len {
        return Err(PoolTreeError::InvalidRootIndex);
    }
    if len == 1 && index != cursor as usize {
        return Err(PoolTreeError::InvalidRootIndex);
    }

    let base = base_offset + index * 32;
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[base..base + 32]);
    if root.iter().all(|byte| *byte == 0) {
        return Err(PoolTreeError::InvalidRootIndex);
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
fn nullifier_root_history_meta_relative_offset() -> usize {
    nullifier_root_history_meta_offset() - state_sub_tree_offset()
}

#[inline]
fn nullifier_root_history_relative_offset() -> usize {
    nullifier_root_history_offset() - state_sub_tree_offset()
}

#[inline]
fn nullifier_next_index_relative_offset() -> usize {
    nullifier_next_index_offset() - state_sub_tree_offset()
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

#[cfg(test)]
mod tests {
    use super::INITIAL_NULLIFIER_ROOT;

    // Parity tripwire: this is the seed root of an empty height-40 indexed
    // nullifier tree. It MUST equal protocol.NewNullifierTree().Root() on the
    // Go side, which is pinned to the same value by
    // TestInitialNullifierRootMatchesProgramConstant. If either side drifts the
    // first batch_update fails on an old_root mismatch, so both pin this hex.
    #[test]
    fn initial_nullifier_root_is_pinned() {
        let expected: [u8; 32] = [
            0x1d, 0x8e, 0x71, 0xa6, 0x01, 0xb3, 0xe8, 0xde, 0xbb, 0xba, 0x9b, 0x55, 0x7b, 0x83,
            0x69, 0xc7, 0xf4, 0x04, 0xae, 0x57, 0xbe, 0xbf, 0x08, 0x52, 0x23, 0x6b, 0x07, 0x28,
            0x20, 0x95, 0x42, 0x77,
        ];
        assert_eq!(INITIAL_NULLIFIER_ROOT, expected);
    }
}
