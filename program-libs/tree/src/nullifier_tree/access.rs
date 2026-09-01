use std::mem::size_of;

use crate::nullifier_tree::{
    constants::NUM_BATCHES, error::NullifierTreeError, layout::NullifierTreeLayout,
};

impl<const ZKP_BATCHES: usize> NullifierTreeLayout<ZKP_BATCHES> {
    /// Validates the invariants required for safe queue rotation and natural
    /// root-history overwrite. Every loader must run this before the layout is
    /// used; the tree operations assume it held.
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

    /// Return the latest root index.
    pub fn get_root_index(&self) -> u32 {
        self.latest_root_index() as u32
    }

    /// Return the latest root of the tree.
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

    /// Return a stored queue hash-chain for a pending ZKP batch.
    pub fn get_hash_chain(&self, batch_index: usize, zkp_batch_index: usize) -> Option<[u8; 32]> {
        self.batches.get(batch_index)?.hash_chain(zkp_batch_index)
    }

    /// Checks whether `num_leaves` values fit in the remaining tree capacity.
    pub fn tree_is_full(&self, num_leaves: u64) -> bool {
        match self.next_index.checked_add(num_leaves) {
            Some(end_index) => end_index > self.capacity,
            None => true,
        }
    }
}

/// The Merkle tree account is a single zero-copy cast, so its size is fully
/// determined by the layout const generics.
pub fn get_merkle_tree_account_size<const ZKP_BATCHES: usize>() -> usize {
    size_of::<NullifierTreeLayout<ZKP_BATCHES>>()
}

/// Byte-slice entry points for tests and benchmarks. Programs hold a typed
/// layout (see `zolana_tree::TreeAccount`) and call the layout methods directly.
#[cfg(feature = "test-only")]
pub mod test_utils {
    use super::*;
    use crate::nullifier_tree::error::NullifierTreeError;

    pub fn init_tree_account_data<const ZKP_BATCHES: usize>(
        account_data: &mut [u8],
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
    ) -> Result<&mut NullifierTreeLayout<ZKP_BATCHES>, NullifierTreeError> {
        let layout = cast_tree_account_data(account_data)?;
        layout.init(input_queue_batch_size, input_queue_zkp_batch_size, height)?;
        Ok(layout)
    }

    pub fn load_tree_account_data<const ZKP_BATCHES: usize>(
        account_data: &mut [u8],
    ) -> Result<&mut NullifierTreeLayout<ZKP_BATCHES>, NullifierTreeError> {
        let layout = cast_tree_account_data::<ZKP_BATCHES>(account_data)?;
        layout.validate()?;
        Ok(layout)
    }

    fn cast_tree_account_data<const ZKP_BATCHES: usize>(
        account_data: &mut [u8],
    ) -> Result<&mut NullifierTreeLayout<ZKP_BATCHES>, NullifierTreeError> {
        if account_data.len() != size_of::<NullifierTreeLayout<ZKP_BATCHES>>() {
            return Err(NullifierTreeError::InvalidAccountSize);
        }
        wincode::deserialize_mut(account_data).map_err(|_| NullifierTreeError::InvalidAccountSize)
    }
}
