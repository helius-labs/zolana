use zolana_hasher::primitives::is_canonical_bn254_scalar_be;

use crate::nullifier_tree::{error::NullifierTreeError, layout::NullifierTreeLayout};

impl<const ZKP_BATCHES: usize> NullifierTreeLayout<ZKP_BATCHES> {
    pub fn insert_nullifier_into_queue(
        &mut self,
        nullifier: &[u8; 32],
    ) -> Result<u64, NullifierTreeError> {
        if !is_canonical_bn254_scalar_be(nullifier) {
            return Err(NullifierTreeError::NonCanonicalFieldElement);
        }
        let queue_index = self.checked_next_queue_index()?;
        let batch_size = self.batch_size;
        let current_batch = self.get_current_batch_mut()?;
        current_batch.ensure_ready_to_fill(batch_size)?;
        current_batch.add_to_hash_chain(nullifier)?;

        self.increment_currently_processing_batch_index_if_full()?;

        self.increment_queue_next_index();
        Ok(queue_index)
    }

    fn checked_next_queue_index(&self) -> Result<u64, NullifierTreeError> {
        let queue_index = self.queue_next_index;
        let leaf_index = queue_index
            .checked_add(1)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;
        if leaf_index >= self.capacity {
            return Err(NullifierTreeError::TreeIsFull);
        }
        Ok(queue_index)
    }

    /// Number of leaves not yet reserved by the queue. Reservations count
    /// values already queued but not yet applied to the Merkle tree.
    pub fn remaining_queue_capacity(&self) -> Result<u64, NullifierTreeError> {
        let next_leaf_index = self
            .queue_next_index
            .checked_add(1)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;
        self.capacity
            .checked_sub(next_leaf_index)
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    fn increment_queue_next_index(&mut self) {
        self.queue_next_index += 1;
    }
}
