use zolana_hasher::hash_chain::create_hash_chain_from_array;
use zolana_merkle_tree_metadata::{
    errors::MerkleTreeMetadataError, events::batch::BatchAddressAppendEvent, TreeType,
};

use crate::{
    errors::BatchedMerkleTreeError,
    merkle_tree::{BatchedMerkleTreeAccount, InstructionDataAddressAppendInputs},
    verify::verify_batch_address_update,
    zero_copy::ChangelogEntry,
};

impl<'a, const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize>
    BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>
{
    /// Verify one address-append proof and apply every now-applicable cached
    /// update.
    ///
    /// Steps:
    /// 1. Reject non-address trees.
    /// 2. Verify the proof and cache it in the changelog. A replayed proof
    ///    caches nothing, so the apply pass is skipped and an empty result
    ///    returned.
    /// 3. Apply cached updates in order: the just-submitted one and any it
    ///    unblocks. Entries that do not match the live tree are skipped, not
    ///    errors.
    pub fn update_tree_from_address_queue(
        &mut self,
        instruction_data: InstructionDataAddressAppendInputs,
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        // 1. Reject non-address trees.
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        // 2. Verify the proof and cache it in the changelog.
        if !self.submit_address_update(&instruction_data)? {
            return Ok(None);
        }
        // 3. Apply cached updates in order.
        self.apply_cached_changelog_updates()
    }

    /// Verify one address-append proof and cache it in the changelog at its zkp
    /// batch index. Returns `true` when a new entry was cached, or `false` when
    /// the update is already applied (its StartIndex is behind the live next
    /// index) or already cached (an occupied entry with this StartIndex exists);
    /// a replayed proof is then a no-op.
    ///
    /// Steps:
    /// 1. Validate the zkp batch index and that its hash chain is finalized.
    /// 2. Reconstruct the proof's StartIndex, the tree next index this zkp batch
    ///    writes at.
    /// 3. Return `false` if the update is already applied or already cached.
    /// 4. Rebuild the public input hash and verify the proof.
    /// 5. Store the changelog entry, keyed by StartIndex, at its zkp batch index.
    fn submit_address_update(
        &mut self,
        instruction_data: &InstructionDataAddressAppendInputs,
    ) -> Result<bool, BatchedMerkleTreeError> {
        let zkp_batch_size = self.queue_batches.zkp_batch_size;
        let submit_slot = self.queue_batches.pending_batch_index as usize;

        let (num_full_zkp_batches, num_inserted_zkp_batches) = {
            let batch = self
                .queue_batches
                .batches
                .get(submit_slot)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            (batch.num_full_zkp_batches, batch.get_num_inserted_zkps())
        };

        // 1. Validate the zkp batch index and that its hash chain is finalized.
        let changelog_capacity = self
            .layout
            .changelog
            .get(submit_slot)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?
            .data
            .len();
        let submit_idx = instruction_data.hash_chain_index as usize;
        if submit_idx >= changelog_capacity {
            return Err(BatchedMerkleTreeError::ChangelogIndexOutOfRange);
        }
        if (submit_idx as u64) >= num_full_zkp_batches {
            return Err(BatchedMerkleTreeError::HashChainNotReady);
        }

        // 2. Reconstruct the proof's StartIndex: the tree next index this zkp
        //    batch writes at.
        let next_index_for_proof = (self.next_index as i128
            + (submit_idx as i128 - num_inserted_zkp_batches as i128) * zkp_batch_size as i128)
            as u64;

        // 3. Skip when already applied (StartIndex behind the live next index) or
        //    already cached (occupied entry with this StartIndex).
        let already_applied = next_index_for_proof < self.next_index;
        let already_cached = self
            .layout
            .changelog
            .get(submit_slot)
            .ok_or(BatchedMerkleTreeError::ChangelogIndexOutOfRange)?
            .data
            .get(submit_idx)
            .map(|entry| entry.occupied == 1 && entry.expected_next_index == next_index_for_proof)
            .unwrap_or(false);
        if already_applied || already_cached {
            return Ok(false);
        }

        // 4. Rebuild the public input hash and verify the proof.
        let leaves_hash_chain = *self
            .layout
            .hash_chains
            .get(submit_slot)
            .and_then(|chain| chain.data.get(submit_idx))
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        let mut next_index_bytes = [0u8; 32];
        next_index_bytes[24..].copy_from_slice(next_index_for_proof.to_be_bytes().as_slice());
        let public_input_hash = create_hash_chain_from_array([
            instruction_data.old_root,
            instruction_data.new_root,
            leaves_hash_chain,
            next_index_bytes,
        ])?;
        verify_batch_address_update(
            zkp_batch_size,
            public_input_hash,
            &instruction_data.compressed_proof,
        )?;

        // 5. Store the entry at its zkp batch index. The stored next index is the
        //    proof's StartIndex public input; apply binds it against the live
        //    next index.
        let entry = self
            .layout
            .changelog
            .get_mut(submit_slot)
            .and_then(|chain| chain.data.get_mut(submit_idx))
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        *entry = ChangelogEntry {
            old_root: instruction_data.old_root,
            new_root: instruction_data.new_root,
            leaves_hash_chain,
            expected_next_index: next_index_for_proof,
            occupied: 1,
        };
        Ok(true)
    }

    /// Apply cached changelog updates in order while each one matches the live
    /// tree, accumulating a single cascade `BatchAddressAppendEvent`. Stops
    /// without error at the first entry that is missing, unoccupied, or whose
    /// old root, next index, or hash chain does not match the live tree.
    ///
    /// Steps (per applied zkp batch):
    /// 1. Read the pending zkp batch's changelog entry; stop if missing or empty.
    /// 2. Stop unless the entry's old root, next index, and hash chain match the
    ///    live tree. These are the proof's public inputs, so a match binds the
    ///    entry to a verified transition.
    /// 3. Apply: advance the tree next index and sequence number, append the new
    ///    root, and mark the zkp batch inserted.
    /// 4. Clear the applied changelog slot.
    /// 5. Record the new root in the cascade event.
    fn apply_cached_changelog_updates(
        &mut self,
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        let zkp_batch_size = self.queue_batches.zkp_batch_size;
        // One event covers the whole cascade: shared fields once, one root per
        // applied zkp batch. See `BatchAddressAppendEvent` for how the per-batch
        // values are derived from each root's position.
        let mut event: Option<BatchAddressAppendEvent> = None;
        loop {
            // 1. Read the pending zkp batch's changelog entry; stop if missing or
            //    empty.
            let batch_slot = self.queue_batches.pending_batch_index as usize;
            let idx = self
                .queue_batches
                .batches
                .get(batch_slot)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?
                .get_num_inserted_zkps() as usize;

            let entry = match self
                .layout
                .changelog
                .get(batch_slot)
                .and_then(|chain| chain.data.get(idx))
            {
                Some(entry) if entry.occupied != 0 => *entry,
                _ => break,
            };

            // 2. Stop unless the entry's old root, next index, and hash chain
            //    match the live tree. These are the proof's public inputs, so a
            //    match binds the entry to a verified transition. A cursor entry
            //    can only become applicable by being applied, so a mismatch here
            //    never resolves on its own: clear the slot so a corrected proof
            //    can be resubmitted (submit skips an occupied slot).
            let current_root = match self.get_root() {
                Some(root) => root,
                None => break,
            };
            if entry.old_root != current_root || entry.expected_next_index != self.next_index {
                self.clear_changelog_entry(batch_slot, idx)?;
                break;
            }

            let live_hash_chain = *self
                .layout
                .hash_chains
                .get(batch_slot)
                .and_then(|chain| chain.data.get(idx))
                .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
            if entry.leaves_hash_chain != live_hash_chain {
                self.clear_changelog_entry(batch_slot, idx)?;
                break;
            }

            // 3. Apply: advance the tree and mark the zkp batch inserted.
            self.check_tree_is_full(Some(zkp_batch_size))?;

            let old_next_index = self.next_index;
            self.increment_merkle_tree_next_index(zkp_batch_size);
            self.sequence_number += 1;
            self.append_root(entry.new_root);
            let root_index = self.get_root_index();

            let root_history_capacity = self.root_history_capacity;
            let sequence_number = self.sequence_number;
            let pending_batch_state = self
                .queue_batches
                .batches
                .get_mut(batch_slot)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?
                .mark_as_inserted_in_merkle_tree(
                    sequence_number,
                    root_index,
                    root_history_capacity,
                )?;
            self.layout
                .metadata
                .queue_batches
                .increment_pending_batch_index_if_inserted(pending_batch_state);
            self.zero_out_previous_batch_bloom_filter()?;

            // 4. Clear the applied changelog slot.
            self.clear_changelog_entry(batch_slot, idx)?;

            // 5. Record this root in the cascade event. The first applied zkp
            //    batch fixes the shared fields; later batches only advance the
            //    count and the final root (intermediate roots live in
            //    root_history).
            let event = event.get_or_insert_with(|| BatchAddressAppendEvent {
                merkle_tree_pubkey: self.pubkey().to_bytes(),
                zkp_batch_size: zkp_batch_size as u16,
                old_next_index,
                start_sequence_number: sequence_number,
                first_root_index: root_index,
                num_update: 0,
                first_zkp_batch_index: idx as u32,
                new_root: entry.new_root,
            });
            event.num_update += 1;
            event.new_root = entry.new_root;
        }

        Ok(event)
    }

    /// Reset the changelog entry at `[batch_slot][idx]` to empty (`occupied = 0`),
    /// freeing the slot for a fresh proof.
    fn clear_changelog_entry(
        &mut self,
        batch_slot: usize,
        idx: usize,
    ) -> Result<(), BatchedMerkleTreeError> {
        let slot = self
            .layout
            .changelog
            .get_mut(batch_slot)
            .and_then(|chain| chain.data.get_mut(idx))
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        *slot = ChangelogEntry::default();
        Ok(())
    }
}
