use std::mem::size_of;

use crate::nullifier_tree::{
    constants::NUM_BATCHES, error::NullifierTreeError, layout::NullifierTreeLayout,
};

impl<const ZKP_BATCHES: usize> NullifierTreeLayout<ZKP_BATCHES> {
    /// Validates the invariants queue rotation and root-history overwrite
    /// rely on. Loaders run this before the layout is used; the tree
    /// operations assume it held.
    pub fn validate(&self) -> Result<(), NullifierTreeError> {
        Self::validate_configuration(self.batch_size, self.zkp_batch_size)?;

        if self.root_history.current_index >= ZKP_BATCHES as u64 {
            return Err(NullifierTreeError::InvalidRootHistoryCapacity);
        }

        if self.currently_processing_batch_index >= NUM_BATCHES as u32
            || self.pending_batch_index >= NUM_BATCHES as u64
        {
            return Err(NullifierTreeError::InvalidBatchIndex);
        }
        if self.batches.iter().any(|batch| {
            batch.batch_size != self.batch_size || batch.zkp_batch_size != self.zkp_batch_size
        }) {
            return Err(NullifierTreeError::InvalidBatchConfiguration);
        }
        Ok(())
    }

    fn latest_root_index(&self) -> usize {
        let capacity = self.root_history.roots.len();
        if capacity == 0 {
            return 0;
        }
        (self.root_history.current_index as usize + capacity - 1) % capacity
    }

    pub fn get_root_index(&self) -> u32 {
        self.latest_root_index() as u32
    }

    pub fn get_root(&self) -> Option<[u8; 32]> {
        self.root_history
            .roots
            .get(self.latest_root_index())
            .copied()
    }

    /// Historical root at `index`. Empty slots read as absent, so a caller
    /// cannot pass off a never-written root-history entry as a valid root.
    pub fn root_by_index(&self, index: u16) -> Option<[u8; 32]> {
        let root = *self.root_history.roots.get(usize::from(index))?;
        if root == [0u8; 32] {
            return None;
        }
        Some(root)
    }

    /// Hash chain slot of a ZKP batch: complete, in progress, or zeroed.
    pub fn get_hash_chain(&self, batch_index: usize, zkp_batch_index: usize) -> Option<[u8; 32]> {
        self.batches.get(batch_index)?.hash_chain(zkp_batch_index)
    }

    /// True when `num_leaves` more values would exceed the tree capacity.
    pub fn tree_is_full(&self, num_leaves: u64) -> bool {
        match self.next_index.checked_add(num_leaves) {
            Some(end_index) => end_index > self.capacity,
            None => true,
        }
    }
}

/// The account is a single zero-copy cast, so its size is determined by the
/// layout const generics.
pub fn get_merkle_tree_account_size<const ZKP_BATCHES: usize>() -> usize {
    size_of::<NullifierTreeLayout<ZKP_BATCHES>>()
}
