use std::mem::size_of;

use crate::nullifier_tree::{
    batch::BatchState, constants::NUM_BATCHES, error::NullifierTreeError,
    layout::NullifierTreeLayout,
};

impl<const ZKP_BATCHES: usize> NullifierTreeLayout<ZKP_BATCHES> {
    /// Validates the invariants queue rotation and root-history overwrite
    /// rely on. Loaders run this before the layout is used; the tree
    /// operations assume it held.
    pub fn validate(&self) -> Result<(), NullifierTreeError> {
        Self::validate_configuration(self.batch_size, self.zkp_batch_size)?;

        let capacity = 1u64
            .checked_shl(self.height)
            .ok_or(NullifierTreeError::InvalidHeight)?;
        if self.capacity != capacity {
            return Err(NullifierTreeError::InvalidHeight);
        }
        if self.next_index == 0
            || self.next_index > capacity
            || self.queue_next_index < self.next_index
            || self.queue_next_index > capacity
            || self.close_before_index > self.next_index
        {
            return Err(NullifierTreeError::InvalidIndex);
        }

        let expected_next_index = self
            .sequence_number
            .checked_mul(self.zkp_batch_size)
            .and_then(|inserted| inserted.checked_add(1))
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;
        if self.next_index != expected_next_index {
            return Err(NullifierTreeError::InvalidIndex);
        }

        let zkp_batches_per_batch = u64::try_from(ZKP_BATCHES)
            .map_err(|_| NullifierTreeError::InvalidBatchConfiguration)?;
        let completed_batches = self
            .sequence_number
            .checked_div(zkp_batches_per_batch)
            .ok_or(NullifierTreeError::InvalidBatchConfiguration)?;
        let expected_close_before_index = if completed_batches == 0 {
            0
        } else {
            completed_batches
                .checked_sub(1)
                .and_then(|completed| completed.checked_mul(self.batch_size))
                .and_then(|offset| offset.checked_add(1))
                .ok_or(NullifierTreeError::ArithmeticOverflow)?
        };
        if self.close_before_index != expected_close_before_index {
            return Err(NullifierTreeError::InvalidIndex);
        }

        let root_history_capacity = u64::try_from(self.root_history.roots.len())
            .map_err(|_| NullifierTreeError::InvalidRootHistoryCapacity)?;
        if root_history_capacity == 0
            || self.root_history.current_index >= root_history_capacity
            || self.root_history.current_index
                != (self.sequence_number % root_history_capacity + 1) % root_history_capacity
        {
            return Err(NullifierTreeError::InvalidRootHistoryCapacity);
        }

        if self.currently_processing_batch_index >= NUM_BATCHES as u32
            || self.pending_batch_index >= NUM_BATCHES as u64
        {
            return Err(NullifierTreeError::InvalidBatchIndex);
        }
        for batch in &self.batches {
            batch.validate(self.batch_size, self.zkp_batch_size)?;
        }
        if self.batches[0]
            .start_index
            .abs_diff(self.batches[1].start_index)
            != self.batch_size
        {
            return Err(NullifierTreeError::InvalidBatchConfiguration);
        }

        let pending = self.get_pending_batch()?;
        let pending_next_index = match pending.get_state()? {
            BatchState::Inserted => self.queue_next_index,
            _ => pending
                .get_num_inserted_zkps()
                .checked_mul(self.zkp_batch_size)
                .and_then(|inserted| pending.start_index.checked_add(inserted))
                .ok_or(NullifierTreeError::ArithmeticOverflow)?,
        };
        if self.next_index != pending_next_index {
            return Err(NullifierTreeError::InvalidBatchConfiguration);
        }

        let current = self.get_current_batch()?;
        let current_queue_index = match current.get_state()? {
            BatchState::Fill => current
                .start_index
                .checked_add(current.get_num_inserted_elements()?)
                .ok_or(NullifierTreeError::ArithmeticOverflow)?,
            BatchState::Full | BatchState::Inserted => {
                let rotation = self
                    .batch_size
                    .checked_mul(NUM_BATCHES as u64)
                    .ok_or(NullifierTreeError::ArithmeticOverflow)?;
                current
                    .start_index
                    .checked_add(rotation)
                    .ok_or(NullifierTreeError::ArithmeticOverflow)?
            }
        };
        if self.queue_next_index != current_queue_index {
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
