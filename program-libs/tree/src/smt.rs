use light_hasher::{Hasher, Poseidon};
use wincode::config::{deserialize_mut, Configuration};
use wincode::len::FixIntLen;
use wincode::SchemaRead;

const NEXT_INDEX_OFFSET: usize = 0;
pub const ROOT_OFFSET: usize = 8;
const ROOT_HISTORY_CURSOR_OFFSET: usize = 40;
const ROOT_HISTORY_LEN_OFFSET: usize = 42;
const SUBTREES_LEN_OFFSET: usize = 44;
const SUBTREES_OFFSET: usize = 45;

pub const ROOT_HISTORY_CAPACITY: usize = 200;

// TODO: move to error.rs file, use thiserror
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    BufferTooSmall,
    HeightTooLarge,
    Deserialize,
    AddressInit,
    AlreadyInitialized,
    InvalidOwner,
    NotWritable,
    InvalidDiscriminator,
    Paused,
    InvalidRootIndex,
}

#[derive(SchemaRead)]
pub struct SparseMerkleTree<'a> {
    pub next_index: &'a mut [u8; 8],
    pub root: &'a mut [u8; 32],
    root_history_cursor: &'a mut [u8; 2],
    root_history_len: &'a mut [u8; 2],
    pub subtrees: &'a mut [[u8; 32]],
    root_history: &'a mut [[u8; 32]],
}

impl<'a> SparseMerkleTree<'a> {
    pub fn serialized_size(height: usize) -> usize {
        SUBTREES_OFFSET + height * 32 + 1 + ROOT_HISTORY_CAPACITY * 32
    }

    pub fn serialized_size_from_bytes(bytes: &[u8]) -> Result<usize, TreeError> {
        let height = *bytes
            .get(SUBTREES_LEN_OFFSET)
            .ok_or(TreeError::BufferTooSmall)?;
        Ok(Self::serialized_size(height as usize))
    }

    pub fn from_bytes_mut(bytes: &'a mut [u8]) -> Result<Self, TreeError> {
        let config = Configuration::default().with_length_encoding::<FixIntLen<u8>>();
        deserialize_mut(bytes, config).map_err(|_| TreeError::Deserialize)
    }

    pub fn init(bytes: &mut [u8], height: usize) -> Result<(), TreeError> {
        let height_byte = u8::try_from(height).map_err(|_| TreeError::HeightTooLarge)?;
        let capacity_byte =
            u8::try_from(ROOT_HISTORY_CAPACITY).map_err(|_| TreeError::HeightTooLarge)?;
        let zero_bytes = Poseidon::zero_bytes();
        let empty_root = *zero_bytes.get(height).ok_or(TreeError::HeightTooLarge)?;

        let buffer = bytes
            .get_mut(..Self::serialized_size(height))
            .ok_or(TreeError::BufferTooSmall)?;
        buffer
            .get_mut(NEXT_INDEX_OFFSET..ROOT_OFFSET)
            .ok_or(TreeError::BufferTooSmall)?
            .copy_from_slice(&0u64.to_le_bytes());
        buffer
            .get_mut(ROOT_OFFSET..ROOT_HISTORY_CURSOR_OFFSET)
            .ok_or(TreeError::BufferTooSmall)?
            .copy_from_slice(&empty_root);
        buffer
            .get_mut(ROOT_HISTORY_CURSOR_OFFSET..ROOT_HISTORY_LEN_OFFSET)
            .ok_or(TreeError::BufferTooSmall)?
            .copy_from_slice(&0u16.to_le_bytes());
        buffer
            .get_mut(ROOT_HISTORY_LEN_OFFSET..SUBTREES_LEN_OFFSET)
            .ok_or(TreeError::BufferTooSmall)?
            .copy_from_slice(&1u16.to_le_bytes());
        *buffer
            .get_mut(SUBTREES_LEN_OFFSET)
            .ok_or(TreeError::BufferTooSmall)? = height_byte;
        for (i, zero) in zero_bytes.iter().take(height).enumerate() {
            let start = SUBTREES_OFFSET + i * 32;
            buffer
                .get_mut(start..start + 32)
                .ok_or(TreeError::BufferTooSmall)?
                .copy_from_slice(zero);
        }
        let history_prefix = SUBTREES_OFFSET + height * 32;
        *buffer
            .get_mut(history_prefix)
            .ok_or(TreeError::BufferTooSmall)? = capacity_byte;
        let history_start = history_prefix + 1;
        buffer
            .get_mut(history_start..history_start + 32)
            .ok_or(TreeError::BufferTooSmall)?
            .copy_from_slice(&empty_root);
        Ok(())
    }

    pub fn append(&mut self, leaf: [u8; 32]) {
        let zero_bytes = Poseidon::zero_bytes();
        let mut current_index = self.next_index();
        let mut current_level_hash = leaf;

        for (subtree, zero_byte) in self.subtrees.iter_mut().zip(zero_bytes.iter()) {
            let left;
            let right;
            if current_index % 2 == 0 {
                left = current_level_hash;
                right = *zero_byte;
                *subtree = current_level_hash;
            } else {
                left = *subtree;
                right = current_level_hash;
            }
            current_level_hash = Poseidon::hashv(&[&left, &right]).unwrap();
            current_index /= 2;
        }
        self.root.copy_from_slice(&current_level_hash);
        self.set_next_index(self.next_index() + 1);
        self.push_root(current_level_hash);
    }

    pub fn root(&self) -> [u8; 32] {
        *self.root
    }

    /// Index of the most recently appended root in the history ring buffer.
    pub fn current_root_index(&self) -> u16 {
        u16::from_le_bytes(*self.root_history_cursor)
    }

    /// Historical root at `index`, with the same validity checks the on-chain
    /// proof path relies on (rejects empty slots and out-of-window indices).
    pub fn root_by_index(&self, index: u16) -> Result<[u8; 32], TreeError> {
        let capacity = self.root_history.len();
        let index = index as usize;
        let cursor = usize::from(self.current_root_index());
        let len = usize::from(u16::from_le_bytes(*self.root_history_len));

        if len == 0 || index >= capacity {
            return Err(TreeError::InvalidRootIndex);
        }
        if len < capacity && index >= len {
            return Err(TreeError::InvalidRootIndex);
        }
        if len == 1 && index != cursor {
            return Err(TreeError::InvalidRootIndex);
        }
        let root = *self
            .root_history
            .get(index)
            .ok_or(TreeError::InvalidRootIndex)?;
        if root.iter().all(|byte| *byte == 0) {
            return Err(TreeError::InvalidRootIndex);
        }
        Ok(root)
    }

    pub fn next_index(&self) -> u64 {
        u64::from_le_bytes(*self.next_index)
    }

    pub fn height(&self) -> usize {
        self.subtrees.len()
    }

    fn set_next_index(&mut self, value: u64) {
        self.next_index.copy_from_slice(&value.to_le_bytes());
    }

    fn push_root(&mut self, root: [u8; 32]) {
        let capacity = self.root_history.len();
        if capacity == 0 {
            return;
        }
        let cursor = usize::from(self.current_root_index());
        let len = usize::from(u16::from_le_bytes(*self.root_history_len));
        let next = (cursor + 1) % capacity;
        let next_len = (len + 1).min(capacity);
        if let Some(slot) = self.root_history.get_mut(next) {
            *slot = root;
        }
        self.root_history_cursor
            .copy_from_slice(&(next as u16).to_le_bytes());
        self.root_history_len
            .copy_from_slice(&(next_len as u16).to_le_bytes());
    }
}
