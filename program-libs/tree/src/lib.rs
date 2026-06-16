//! Clean tree types for the shielded pool.
pub mod smt;

pub use light_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData;
pub use smt::{SparseMerkleTree, TreeError};

use light_batched_merkle_tree::initialize_address_tree::{
    get_address_merkle_tree_account_size_from_params, init_batched_address_merkle_tree_account,
};
use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use pinocchio::{AccountView, Address};

const HEADER_LEN: usize = 8;

/// `state` byte values. Writes to the tree are only allowed in `INITIALIZED`.
pub const UNINITIALIZED: u8 = 0;
pub const INITIALIZED: u8 = 1;
pub const PAUSED: u8 = 2;

pub struct TreeAccount<'a> {
    // Account memory layout:
    //   [0]            discriminator (u8)
    //   [1]            state (u8: 0 uninitialized, 1 initialized, 2 paused)
    //   [2..8]         padding
    //   [8..8+S]       utxo_tree: sparse merkle tree
    //                    next_index (u64 LE, 8) | root (32) | subtrees len (u8) | subtrees (len * 32)
    //   [8+S..A]       padding (rounds S up to a multiple of 8 so nullifer_tree is 8-byte aligned)
    //   [A..A+N]       nullifer_tree: batched address tree, N = get_address_merkle_tree_account_size_from_params
    pub discriminator: u8,
    state: &'a mut u8,
    _padding: [u8; 6],
    pub utxo_tree: SparseMerkleTree<'a>,
    pub nullifer_tree: BatchedMerkleTreeAccount<'a>,
}

impl<'a> TreeAccount<'a> {
    /// Total account byte length for the given utxo-tree height and nullifier
    /// params. The account allocator must use this so `init` does not run out of
    /// buffer.
    pub fn account_size(
        utxo_tree_height: u8,
        nullifier_params: InitAddressTreeAccountsInstructionData,
    ) -> usize {
        HEADER_LEN
            + Self::utxo_tree_size(utxo_tree_height)
            + get_address_merkle_tree_account_size_from_params(nullifier_params)
    }

    fn utxo_tree_size(utxo_tree_height: u8) -> usize {
        SparseMerkleTree::serialized_size(utxo_tree_height as usize).next_multiple_of(8)
    }

    /// Byte offset of the state (utxo) tree's current root within the account.
    /// The utxo tree starts right after the account header and stores its root
    /// at [`smt::ROOT_OFFSET`].
    pub const fn state_root_offset() -> usize {
        HEADER_LEN + smt::ROOT_OFFSET
    }

    pub fn init(
        bytes: &'a mut [u8],
        discriminator: u8,
        utxo_tree_height: u8,
        owner: [u8; 32],
        pubkey: [u8; 32],
        nullifier_params: InitAddressTreeAccountsInstructionData,
    ) -> Result<Self, TreeError> {
        let (header, body) = bytes
            .split_at_mut_checked(HEADER_LEN)
            .ok_or(TreeError::BufferTooSmall)?;
        let (discriminator_byte, state, padding) = split_header(header)?;
        if *state != UNINITIALIZED {
            return Err(TreeError::AlreadyInitialized);
        }
        *discriminator_byte = discriminator;
        *state = INITIALIZED;

        let utxo_tree_size = Self::utxo_tree_size(utxo_tree_height);
        let (utxo_bytes, rest) = body
            .split_at_mut_checked(utxo_tree_size)
            .ok_or(TreeError::BufferTooSmall)?;
        let nullifier_size = get_address_merkle_tree_account_size_from_params(nullifier_params);
        let nullifier_bytes = rest
            .get_mut(..nullifier_size)
            .ok_or(TreeError::BufferTooSmall)?;

        SparseMerkleTree::init(utxo_bytes, utxo_tree_height as usize)?;
        let utxo_tree = SparseMerkleTree::from_bytes_mut(utxo_bytes)?;

        let nullifer_tree = init_batched_address_merkle_tree_account(
            owner.into(),
            nullifier_params,
            nullifier_bytes,
            0,
            pubkey.into(),
        )
        .map_err(|_| TreeError::AddressInit)?;

        Ok(Self {
            discriminator,
            state,
            _padding: padding,
            utxo_tree,
            nullifer_tree,
        })
    }

    pub fn from_bytes(bytes: &'a mut [u8], pubkey: [u8; 32]) -> Result<Self, TreeError> {
        let (header, body) = bytes
            .split_at_mut_checked(HEADER_LEN)
            .ok_or(TreeError::BufferTooSmall)?;
        let (discriminator_byte, state, padding) = split_header(header)?;
        let discriminator = *discriminator_byte;

        let utxo_tree_size =
            SparseMerkleTree::serialized_size_from_bytes(body)?.next_multiple_of(8);
        let (utxo_bytes, nullifier_bytes) = body
            .split_at_mut_checked(utxo_tree_size)
            .ok_or(TreeError::BufferTooSmall)?;

        let utxo_tree = SparseMerkleTree::from_bytes_mut(utxo_bytes)?;
        let nullifer_tree =
            BatchedMerkleTreeAccount::address_from_bytes(nullifier_bytes, &pubkey.into())
                .map_err(|_| TreeError::AddressInit)?;

        Ok(Self {
            discriminator,
            state,
            _padding: padding,
            utxo_tree,
            nullifer_tree,
        })
    }

    /// Load a writable tree from its account, checking program ownership, the
    /// discriminator, and that the tree is not paused. Use this on every write
    /// path that must be frozen while paused.
    pub fn from_account_view_mut(
        account: &'a mut AccountView,
        program_id: &Address,
        discriminator: u8,
    ) -> Result<Self, TreeError> {
        let tree = Self::load_checked(account, program_id, discriminator)?;
        if tree.is_paused() {
            return Err(TreeError::Paused);
        }
        Ok(tree)
    }

    /// Like [`Self::from_account_view_mut`] but does not reject a paused tree.
    /// `pause_tree` needs this to load a paused tree in order to unpause it.
    pub fn from_account_view_mut_allow_paused(
        account: &'a mut AccountView,
        program_id: &Address,
        discriminator: u8,
    ) -> Result<Self, TreeError> {
        Self::load_checked(account, program_id, discriminator)
    }

    fn load_checked(
        account: &'a mut AccountView,
        program_id: &Address,
        discriminator: u8,
    ) -> Result<Self, TreeError> {
        if !account.is_writable() {
            return Err(TreeError::NotWritable);
        }
        if !account.owned_by(program_id) {
            return Err(TreeError::InvalidOwner);
        }
        let pubkey = account.address().to_bytes();
        // SAFETY: `account` is borrowed exclusively (`&mut`), so no other live
        // borrow of its data exists while the returned view is in scope.
        let bytes = unsafe { account.borrow_unchecked_mut() };
        if bytes.first() != Some(&discriminator) {
            return Err(TreeError::InvalidDiscriminator);
        }
        Self::from_bytes(bytes, pubkey)
    }

    pub fn get_utxo_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        self.utxo_tree.root_by_index(index)
    }

    pub fn get_nullifier_tree_root(&self, index: u16) -> Result<[u8; 32], TreeError> {
        let root = self
            .nullifer_tree
            .get_root_by_index(usize::from(index))
            .copied()
            .ok_or(TreeError::InvalidRootIndex)?;
        if root == [0u8; 32] {
            return Err(TreeError::InvalidRootIndex);
        }
        Ok(root)
    }

    pub fn state(&self) -> u8 {
        *self.state
    }

    pub fn is_paused(&self) -> bool {
        *self.state == PAUSED
    }

    pub fn set_paused(&mut self, paused: bool) {
        *self.state = if paused { PAUSED } else { INITIALIZED };
    }
}

/// Split the 8-byte header into `(discriminator, state, padding)`, borrowing the
/// state byte mutably so `set_paused` can write through it.
fn split_header(header: &mut [u8]) -> Result<(&mut u8, &mut u8, [u8; 6]), TreeError> {
    let (discriminator, rest) = header.split_first_mut().ok_or(TreeError::BufferTooSmall)?;
    let (state, padding_slice) = rest.split_first_mut().ok_or(TreeError::BufferTooSmall)?;
    let mut padding = [0u8; 6];
    padding.copy_from_slice(padding_slice.get(..6).ok_or(TreeError::BufferTooSmall)?);
    Ok((discriminator, state, padding))
}
