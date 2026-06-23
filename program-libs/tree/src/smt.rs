use core::mem::{size_of, MaybeUninit};

use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};
use zolana_hasher::{Hasher, Poseidon};

pub const ROOT_OFFSET: usize = 8;

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UtxoTreeLayout<const HEIGHT: usize> {
    pub next_index: [u8; 8],
    pub root: [u8; 32],
    pub root_history_cursor: [u8; 2],
    pub root_history_len: [u8; 2],
    pub subtrees_len: u8,
    pub subtrees: [[u8; 32]; HEIGHT],
    pub root_history_capacity: u8,
    pub root_history: [[u8; 32]; ROOT_HISTORY_CAPACITY],
}

unsafe impl<C: ConfigCore, const HEIGHT: usize> ZeroCopy<C> for UtxoTreeLayout<HEIGHT> {}

unsafe impl<'de, C: ConfigCore, const HEIGHT: usize> SchemaRead<'de, C> for UtxoTreeLayout<HEIGHT> {
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: size_of::<Self>(),
        zero_copy: true,
    };

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
        unsafe { Ok(reader.copy_into_t(dst)?) }
    }
}

impl<const HEIGHT: usize> UtxoTreeLayout<HEIGHT> {
    pub const fn serialized_size(height: usize) -> usize {
        45 + height * 32 + 1 + ROOT_HISTORY_CAPACITY * 32
    }

    pub fn init(&mut self, height: usize) -> Result<(), TreeError> {
        if height != HEIGHT {
            return Err(TreeError::HeightTooLarge);
        }
        let height_byte = u8::try_from(height).map_err(|_| TreeError::HeightTooLarge)?;
        let capacity_byte =
            u8::try_from(ROOT_HISTORY_CAPACITY).map_err(|_| TreeError::HeightTooLarge)?;
        let zero_bytes = Poseidon::zero_bytes();
        let empty_root = *zero_bytes.get(height).ok_or(TreeError::HeightTooLarge)?;

        self.next_index = 0u64.to_le_bytes();
        self.root = empty_root;
        self.root_history_cursor = 0u16.to_le_bytes();
        self.root_history_len = 1u16.to_le_bytes();
        self.subtrees_len = height_byte;
        for (subtree, zero) in self.subtrees.iter_mut().zip(zero_bytes.iter()) {
            *subtree = *zero;
        }
        self.root_history_capacity = capacity_byte;
        if let Some(slot) = self.root_history.get_mut(0) {
            *slot = empty_root;
        }
        Ok(())
    }

    pub fn append(&mut self, leaf: [u8; 32]) {
        self.append_batch([&leaf]);
    }

    pub fn append_batch<'l, I>(&mut self, leaves: I)
    where
        I: IntoIterator<Item = &'l [u8; 32]>,
    {
        let zero_bytes = Poseidon::zero_bytes();
        let mut leaves = leaves.into_iter().peekable();

        while let Some(leaf) = leaves.next() {
            let is_last = leaves.peek().is_none();
            let mut current_index = self.next_index();
            let mut current_level_hash = *leaf;

            for (subtree, zero_byte) in self.subtrees.iter_mut().zip(zero_bytes.iter()) {
                if current_index.is_multiple_of(2) {
                    *subtree = current_level_hash;
                    if !is_last {
                        break;
                    }
                    current_level_hash =
                        Poseidon::hashv(&[&current_level_hash, zero_byte]).unwrap();
                } else {
                    let left = *subtree;
                    current_level_hash = Poseidon::hashv(&[&left, &current_level_hash]).unwrap();
                }
                current_index /= 2;
            }

            if is_last {
                self.root = current_level_hash;
                self.push_root(current_level_hash);
            } else {
                self.push_root([0u8; 32]);
            }
            self.set_next_index(self.next_index() + 1);
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Index of the most recently appended root in the history ring buffer.
    pub fn current_root_index(&self) -> u16 {
        u16::from_le_bytes(self.root_history_cursor)
    }

    /// Historical root at `index`, with the same validity checks the on-chain
    /// proof path relies on (rejects empty slots and out-of-window indices).
    pub fn root_by_index(&self, index: u16) -> Result<[u8; 32], TreeError> {
        let capacity = self.root_history.len();
        let index = index as usize;
        let cursor = usize::from(self.current_root_index());
        let len = usize::from(u16::from_le_bytes(self.root_history_len));

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
        u64::from_le_bytes(self.next_index)
    }

    pub fn height(&self) -> usize {
        self.subtrees.len()
    }

    fn set_next_index(&mut self, value: u64) {
        self.next_index = value.to_le_bytes();
    }

    fn push_root(&mut self, root: [u8; 32]) {
        let capacity = self.root_history.len();
        if capacity == 0 {
            return;
        }
        let cursor = usize::from(self.current_root_index());
        let len = usize::from(u16::from_le_bytes(self.root_history_len));
        let next = (cursor + 1) % capacity;
        let next_len = (len + 1).min(capacity);
        if let Some(slot) = self.root_history.get_mut(next) {
            *slot = root;
        }
        self.root_history_cursor = (next as u16).to_le_bytes();
        self.root_history_len = (next_len as u16).to_le_bytes();
    }
}
