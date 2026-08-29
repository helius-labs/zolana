use std::mem::size_of;

use crate::{
    constants::NUM_BATCHES,
    errors::NullifierTreeError,
    layout::{NullifierTreeLayout, QueueBatches},
};

impl<const ZKP: usize> NullifierTreeLayout<ZKP> {
    /// Validates the invariants required for safe queue rotation and natural
    /// root-history overwrite. Every loader must run this before the layout is
    /// used; the tree operations assume it held.
    pub fn validate(&self) -> Result<(), NullifierTreeError> {
        let queue = &self.metadata.queue_batches;
        QueueBatches::validate_configuration::<ZKP>(queue.batch_size, queue.zkp_batch_size)?;

        if self.root_history.current_index >= ZKP as u64 {
            return Err(NullifierTreeError::InvalidRootHistoryCapacity);
        }

        if queue.currently_processing_batch_index >= NUM_BATCHES as u64
            || queue.pending_batch_index >= NUM_BATCHES as u64
        {
            return Err(NullifierTreeError::InvalidBatchIndex);
        }
        if queue.reserved != NUM_BATCHES as u64
            || queue.batches.iter().any(|batch| {
                batch.batch_size != queue.batch_size || batch.zkp_batch_size != queue.zkp_batch_size
            })
        {
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

    /// Return a stored queue hash-chain for a pending ZKP batch.
    pub fn get_hash_chain(&self, batch_index: usize, zkp_batch_index: usize) -> Option<[u8; 32]> {
        self.hash_chains
            .get(batch_index)
            .and_then(|chain| chain.get(zkp_batch_index))
            .copied()
    }

    /// Checks whether `num_leaves` values fit in the remaining tree capacity.
    pub fn tree_is_full(&self, num_leaves: u64) -> bool {
        match self.metadata.next_index.checked_add(num_leaves) {
            Some(end_index) => end_index > self.metadata.capacity,
            None => true,
        }
    }
}

/// The Merkle tree account is a single zero-copy cast, so its size is fully
/// determined by the layout const generics.
pub fn get_merkle_tree_account_size<const ZKP: usize>() -> usize {
    size_of::<NullifierTreeLayout<ZKP>>()
}

/// Byte-slice entry points for tests and benchmarks. Programs hold a typed
/// layout (see `zolana_tree::TreeAccount`) and call the layout methods directly.
#[cfg(feature = "test-only")]
pub mod test_utils {
    use super::*;
    use crate::{errors::NullifierTreeError, layout::TreeType};

    pub fn init_tree_account_data<const ZKP: usize>(
        account_data: &mut [u8],
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        address_init_root: Option<[u8; 32]>,
    ) -> Result<&mut NullifierTreeLayout<ZKP>, NullifierTreeError> {
        let layout = cast_tree_account_data(account_data)?;
        layout.init(
            input_queue_batch_size,
            input_queue_zkp_batch_size,
            height,
            tree_type,
            address_init_root,
        )?;
        Ok(layout)
    }

    pub fn load_tree_account_data<const ZKP: usize>(
        account_data: &mut [u8],
    ) -> Result<&mut NullifierTreeLayout<ZKP>, NullifierTreeError> {
        let layout = cast_tree_account_data::<ZKP>(account_data)?;
        if layout.metadata.tree_type != TreeType::AddressV2 as u64 {
            return Err(NullifierTreeError::InvalidTreeType);
        }
        layout.validate()?;
        Ok(layout)
    }

    fn cast_tree_account_data<const ZKP: usize>(
        account_data: &mut [u8],
    ) -> Result<&mut NullifierTreeLayout<ZKP>, NullifierTreeError> {
        if account_data.len() != size_of::<NullifierTreeLayout<ZKP>>() {
            return Err(NullifierTreeError::InvalidAccountSize);
        }
        wincode::deserialize_mut(account_data).map_err(|_| NullifierTreeError::InvalidAccountSize)
    }
}
