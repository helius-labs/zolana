use zolana_hasher::primitives::is_canonical_bn254_scalar_be;

use crate::{
    batch::BatchState,
    errors::NullifierTreeError,
    layout::{NullifierTreeLayout, TreeType},
};

impl<const ZKP: usize> NullifierTreeLayout<ZKP> {
    pub fn insert_nullifier_into_queue(
        &mut self,
        nullifier: &[u8; 32],
    ) -> Result<u64, NullifierTreeError> {
        if self.metadata.tree_type != TreeType::AddressV2 as u64 {
            return Err(NullifierTreeError::InvalidTreeType);
        }
        if !is_canonical_bn254_scalar_be(nullifier) {
            return Err(NullifierTreeError::NonCanonicalFieldElement);
        }

        let queue_index = self.metadata.queue_batches.next_index;
        let leaf_index = queue_index
            .checked_add(1)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;
        if leaf_index != self.next_queued_leaf_index()? {
            return Err(NullifierTreeError::QueueIndexMismatch);
        }
        self.check_queue_next_index_reached_tree_capacity()?;
        self.insert_into_current_queue_batch(nullifier)?;
        self.increment_queue_next_index();
        Ok(queue_index)
    }

    /// Insert a value into the current input/address queue batch's hash chain.
    ///
    /// Steps:
    /// 1. Check that the current batch is ready. If it is inserted, reuse it: its
    ///    coverage starts one rotation after its previous start.
    /// 2. Insert value into the current batch.
    /// 3. If batch is full, increment currently_processing_batch_index.
    fn insert_into_current_queue_batch(
        &mut self,
        value: &[u8; 32],
    ) -> Result<(), NullifierTreeError> {
        let batch_index = self.metadata.queue_batches.currently_processing_batch_index as usize;
        let rotation = self.metadata.queue_batches.rotation()?;
        // `metadata` and `hash_chains` are disjoint fields of the layout, so
        // the queue and its hash chain can be borrowed mutably at once.
        let hash_chain = self
            .hash_chains
            .get_mut(batch_index)
            .ok_or(NullifierTreeError::InvalidBatchIndex)?;
        let queue = &mut self.metadata.queue_batches;
        let current_batch = queue.get_current_batch_mut()?;

        // 1. Check that the current batch is ready (BatchState::Fill).
        //      1.1. If the current batch is inserted, advance it to fill.
        match current_batch.checked_state()? {
            BatchState::Fill => {}
            BatchState::Inserted => {
                let start_index = current_batch
                    .start_index
                    .checked_add(rotation)
                    .ok_or(NullifierTreeError::ArithmeticOverflow)?;
                current_batch.advance_state_to_fill(start_index)?;
            }
            BatchState::Full => {
                #[cfg(feature = "log")]
                solana_msg::msg!("current batch {:?} is full", current_batch);
                return Err(NullifierTreeError::BatchNotReady);
            }
        }

        // 2. Insert value into the current batch.
        current_batch.add_to_hash_chain(value, hash_chain)?;

        // 3. If batch is full, increment currently_processing_batch_index.
        queue.increment_currently_processing_batch_index_if_full()?;

        Ok(())
    }

    /// Checks that the next queued value still fits into the tree. Queued
    /// values are appended in queue order starting at the current batch's
    /// `start_index` (the init element occupies leaf 0, so queue sequence
    /// numbers are one behind tree leaf indices); the value fits iff that
    /// leaf index is below `capacity`.
    fn check_queue_next_index_reached_tree_capacity(&self) -> Result<(), NullifierTreeError> {
        let leaf_index = self.next_queued_leaf_index()?;
        if leaf_index >= self.metadata.capacity {
            return Err(NullifierTreeError::TreeIsFull);
        }
        Ok(())
    }

    /// Leaf index reserved by the next queue insertion. This includes values
    /// already queued but not yet applied to the Merkle tree. An `Inserted`
    /// current batch is about to be reused one rotation ahead, so its next
    /// leaf is `start_index + NUM_BATCHES * batch_size`. A `Full` current
    /// batch means both batches are full: the next value can only go into this
    /// batch once it is inserted and reused, so it reserves the same leaf.
    pub fn next_queued_leaf_index(&self) -> Result<u64, NullifierTreeError> {
        let queue = &self.metadata.queue_batches;
        let current_batch = queue.get_current_batch()?;
        let offset = match current_batch.checked_state()? {
            BatchState::Fill => current_batch.get_num_inserted_elements(),
            BatchState::Full | BatchState::Inserted => queue.rotation()?,
        };
        current_batch
            .start_index
            .checked_add(offset)
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    /// Number of leaves not yet reserved by the queue.
    pub fn remaining_queue_capacity(&self) -> Result<u64, NullifierTreeError> {
        self.metadata
            .capacity
            .checked_sub(self.next_queued_leaf_index()?)
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    fn increment_queue_next_index(&mut self) {
        self.metadata.queue_batches.next_index += 1;
    }
}
