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
        let queue_index = self.checked_next_queue_index()?;

        let rotation = self.metadata.queue_batches.rotation()?;
        let current_batch = self.metadata.queue_batches.get_current_batch_mut()?;
        current_batch.ensure_ready_to_fill(rotation)?;
        current_batch.add_to_hash_chain(nullifier)?;

        self.metadata
            .queue_batches
            .increment_currently_processing_batch_index_if_full()?;

        self.increment_queue_next_index();
        Ok(queue_index)
    }

    /// Queue index the next value takes, once both queue invariants hold: the
    /// queue counter must agree with the leaf index the current batch reserves
    /// next (the init element occupies leaf 0, so queue indices are one behind
    /// tree leaf indices), and that leaf must still be inside the tree.
    fn checked_next_queue_index(&self) -> Result<u64, NullifierTreeError> {
        let queue_index = self.metadata.queue_batches.next_index;
        let leaf_index = queue_index
            .checked_add(1)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;
        if leaf_index != self.next_queued_leaf_index()? {
            return Err(NullifierTreeError::QueueIndexMismatch);
        }
        if leaf_index >= self.metadata.capacity {
            return Err(NullifierTreeError::TreeIsFull);
        }
        Ok(queue_index)
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
