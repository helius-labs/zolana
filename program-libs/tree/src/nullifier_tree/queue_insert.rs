use zolana_hasher::primitives::is_canonical_bn254_scalar_be;

use crate::nullifier_tree::{error::NullifierTreeError, layout::NullifierTreeLayout};

impl<const ZKP_BATCHES: usize> NullifierTreeLayout<ZKP_BATCHES> {
    /// Add one nullifier to the current batch's current hash chain and return
    /// the queue index it reserved. The queue index is the leaf index the
    /// value takes once appended; leaf 0 is the init sentinel, so it is never
    /// zero.
    ///
    /// Steps (spec "Insert into queue" step in parentheses; steps 1 and 7-9
    /// there are the program's):
    /// 1. Reject a non-canonical BN254 scalar (1).
    /// 2. Reserve queue index `q`; require `q < capacity` (3).
    /// 3. Require the current batch to be `Fill`, reusing an `Inserted` batch
    ///    first: counters reset, `start_index` advances by
    ///    `NUM_BATCHES * batch_size`. `Full` is an error (2).
    /// 4. Extend the current hash chain; a completed zkp batch starts the next
    ///    chain, and the last one sets the batch `Full` (4-5).
    /// 5. If the batch is `Full`, advance the current batch index (5).
    /// 6. Increment `queue_next_index` and return `q` (6).
    pub fn insert_nullifier_into_queue(
        &mut self,
        nullifier: &[u8; 32],
    ) -> Result<u64, NullifierTreeError> {
        // 1. Reject a non-canonical BN254 scalar.
        if !is_canonical_bn254_scalar_be(nullifier) {
            return Err(NullifierTreeError::NonCanonicalFieldElement);
        }
        // 2. Reserve queue index `q`; require `q < capacity`.
        let queue_index = self.checked_next_queue_index()?;
        // 3. Require the current batch to be `Fill`, reusing an `Inserted`
        //    batch first.
        let batch_size = self.batch_size;
        let current_batch = self.get_current_batch_mut()?;
        current_batch.ensure_ready_to_fill(batch_size)?;
        // 4. Extend the current hash chain.
        current_batch.add_to_hash_chain(nullifier)?;

        // 5. If the batch is `Full`, advance the current batch index.
        self.increment_currently_processing_batch_index_if_full()?;

        // 6. Increment `queue_next_index` and return `q`.
        self.increment_queue_next_index();
        Ok(queue_index)
    }

    fn checked_next_queue_index(&self) -> Result<u64, NullifierTreeError> {
        let queue_index = self.queue_next_index;
        if queue_index >= self.capacity {
            return Err(NullifierTreeError::TreeIsFull);
        }
        Ok(queue_index)
    }

    /// Number of leaves not yet reserved by the queue. Reservations count
    /// values already queued but not yet applied to the Merkle tree.
    pub fn remaining_queue_capacity(&self) -> Result<u64, NullifierTreeError> {
        self.capacity
            .checked_sub(self.queue_next_index)
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    fn increment_queue_next_index(&mut self) {
        self.queue_next_index += 1;
    }
}
