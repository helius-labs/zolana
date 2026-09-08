use core::mem::{size_of, MaybeUninit};

use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};
use zolana_hasher::{Hasher, Poseidon};

use crate::error::TreeError;

pub const ROOT_OFFSET: usize = 8;

pub const ROOT_HISTORY_CAPACITY: usize = 500;

const _: () = assert!(ROOT_HISTORY_CAPACITY <= u16::MAX as usize);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UtxoTreeLayout<const HEIGHT: usize> {
    pub next_index: [u8; 8],
    pub root: [u8; 32],
    pub root_history_cursor: u16,
    pub root_history_len: u16,
    pub root_history_capacity: u16,
    pub subtrees_len: u8,
    pub _padding: [u8; 1],
    pub last_update_slot: u64,
    pub subtrees: [[u8; 32]; HEIGHT],
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
    pub fn init(&mut self, height: usize) -> Result<(), TreeError> {
        if height != HEIGHT {
            return Err(TreeError::HeightTooLarge);
        }
        let height_byte = u8::try_from(height).map_err(|_| TreeError::HeightTooLarge)?;
        let capacity =
            u16::try_from(ROOT_HISTORY_CAPACITY).map_err(|_| TreeError::HeightTooLarge)?;
        let zero_bytes = Poseidon::zero_bytes();
        let empty_root = *zero_bytes.get(height).ok_or(TreeError::HeightTooLarge)?;

        self.next_index = 0u64.to_le_bytes();
        self.root = empty_root;
        self.root_history_cursor = 0;
        self.root_history_len = 1;
        self.root_history_capacity = capacity;
        self.subtrees_len = height_byte;
        self._padding = [0];
        self.last_update_slot = 0;
        for (subtree, zero) in self.subtrees.iter_mut().zip(zero_bytes.iter()) {
            *subtree = *zero;
        }
        if let Some(slot) = self.root_history.get_mut(0) {
            *slot = empty_root;
        }
        Ok(())
    }

    pub const fn capacity(&self) -> u64 {
        1u64 << HEIGHT
    }

    /// Appends one leaf and stores its resulting root in the history ring.
    /// Further appends in the same slot overwrite that history entry.
    pub fn append(&mut self, leaf: [u8; 32], slot: u64) -> Result<(), TreeError> {
        self.append_batch([&leaf], slot)
    }

    /// Appends a batch of leaves and stores only its final root. The first
    /// update observed in a new slot advances the history cursor; later
    /// updates in that slot overwrite the current entry. Returns
    /// [`TreeError::TreeIsFull`] once the tree holds `2^HEIGHT` leaves;
    /// appending past that would overwrite the subtrees and produce a garbage
    /// root. Leaves appended before the error stay appended; in the program
    /// the error aborts the instruction.
    pub fn append_batch<'l, I>(&mut self, leaves: I, slot: u64) -> Result<(), TreeError>
    where
        I: IntoIterator<Item = &'l [u8; 32]>,
    {
        let zero_bytes = Poseidon::zero_bytes();
        let mut leaves = leaves.into_iter().peekable();
        // `next_index` changes for every leaf, so capture this before walking
        // the batch. In particular, a multi-leaf first batch must still
        // advance away from the initial empty root at history index 0.
        let is_first_update = self.next_index() == 0;
        if leaves.peek().is_some() && !is_first_update && slot < self.last_update_slot {
            return Err(TreeError::InvalidUpdateSlot);
        }

        while let Some(leaf) = leaves.next() {
            if self.next_index() >= self.capacity() {
                return Err(TreeError::TreeIsFull);
            }
            let is_last = leaves.peek().is_none();
            let mut current_index = self.next_index();
            let mut current_level_hash = *leaf;

            for (subtree, zero_byte) in self.subtrees.iter_mut().zip(zero_bytes.iter()) {
                if current_index.is_multiple_of(2) {
                    *subtree = current_level_hash;
                    if !is_last {
                        break;
                    }
                    current_level_hash = Poseidon::hashv(&[&current_level_hash, zero_byte])
                        .map_err(|_| TreeError::Hash)?;
                } else {
                    let left = *subtree;
                    current_level_hash = Poseidon::hashv(&[&left, &current_level_hash])
                        .map_err(|_| TreeError::Hash)?;
                }
                current_index /= 2;
            }

            // Intermediate roots are not computed; only the batch-final root
            // enters the history.
            if is_last {
                self.root = current_level_hash;
                self.push_root(current_level_hash, slot, is_first_update);
            }
            self.set_next_index(self.next_index() + 1);
        }
        Ok(())
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Index of the most recently appended root in the history ring buffer.
    pub fn current_root_index(&self) -> u16 {
        self.root_history_cursor
    }

    /// Historical root at `index`. Rejects empty slots and indices past the
    /// densely written window.
    pub fn root_by_index(&self, index: u16) -> Result<[u8; 32], TreeError> {
        let capacity = self.root_history.len();
        let index = index as usize;
        let len = usize::from(self.root_history_len);

        if len == 0 || index >= capacity {
            return Err(TreeError::InvalidRootIndex);
        }
        if len < capacity && index >= len {
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

    fn push_root(&mut self, root: [u8; 32], slot: u64, is_first_update: bool) {
        let capacity = self.root_history.len();
        if capacity == 0 {
            return;
        }
        let cursor = usize::from(self.current_root_index());
        if !is_first_update && slot == self.last_update_slot {
            if let Some(history_slot) = self.root_history.get_mut(cursor) {
                *history_slot = root;
            }
            return;
        }
        let len = usize::from(self.root_history_len);
        let next = (cursor + 1) % capacity;
        let next_len = (len + 1).min(capacity);
        if let Some(history_slot) = self.root_history.get_mut(next) {
            *history_slot = root;
        }
        self.root_history_cursor = next as u16;
        self.root_history_len = next_len as u16;
        self.last_update_slot = slot;
    }
}
