use zolana_hasher::hash_chain::create_hash_chain_from_array;

use crate::{
    errors::{BatchedMerkleTreeError, MerkleTreeMetadataError},
    events::BatchAddressAppendEvent,
    merkle_tree::{BatchedMerkleTreeAccount, InstructionDataAddressAppendInputs},
    merkle_tree_metadata::TreeType,
    verify::{
        verify_batch_address_update, verify_batch_address_update_many, CompressedProof,
    },
    zero_copy::CachedTreeUpdate,
};

struct ReadyUpdate {
    zkp_batch_index: usize,
    public_input_hash: [u8; 32],
    old_root: [u8; 32],
    new_root: [u8; 32],
    compressed_proof: CompressedProof,
}

impl<'a, const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize>
    BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>
{
    /// Legacy: one proof, solo verify, then apply cascade.
    pub fn update_tree_from_address_queue(
        &mut self,
        instruction_data: InstructionDataAddressAppendInputs,
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        if !self.verify_proof_cache_update(&instruction_data)? {
            return Ok(None);
        }
        self.apply_cached_tree_updates()
    }

    /// Batch incarnation: one RLC over N proofs, then apply. Solo path unchanged.
    pub fn update_tree_from_address_queue_many(
        &mut self,
        items: &[InstructionDataAddressAppendInputs],
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        if items.is_empty() {
            return Ok(None);
        }
        let zkp_batch_size = self.queue_batches.zkp_batch_size;
        let mut ready = Vec::with_capacity(items.len());
        for item in items {
            if let Some(u) = self.prepare_update(item)? {
                ready.push(u);
            }
        }
        if ready.is_empty() {
            return Ok(None);
        }
        let batch_items: Vec<([u8; 32], &CompressedProof)> = ready
            .iter()
            .map(|u| (u.public_input_hash, &u.compressed_proof))
            .collect();
        verify_batch_address_update_many(zkp_batch_size, &batch_items)?;
        for u in &ready {
            self.cache_ready_update(u)?;
        }
        self.apply_cached_tree_updates()
    }

    fn verify_proof_cache_update(
        &mut self,
        instruction_data: &InstructionDataAddressAppendInputs,
    ) -> Result<bool, BatchedMerkleTreeError> {
        let Some(ready) = self.prepare_update(instruction_data)? else {
            return Ok(false);
        };
        verify_batch_address_update(
            self.queue_batches.zkp_batch_size,
            ready.public_input_hash,
            &ready.compressed_proof,
        )?;
        self.cache_ready_update(&ready)?;
        Ok(true)
    }

    fn prepare_update(
        &self,
        instruction_data: &InstructionDataAddressAppendInputs,
    ) -> Result<Option<ReadyUpdate>, BatchedMerkleTreeError> {
        let zkp_batch_size = self.queue_batches.zkp_batch_size;
        let pending_batch_index = self.queue_batches.pending_batch_index as usize;

        let (num_full_zkp_batches, num_inserted_zkp_batches) = {
            let batch = self
                .queue_batches
                .batches
                .get(pending_batch_index)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            (batch.num_full_zkp_batches, batch.get_num_inserted_zkps())
        };

        let cached_tree_update_capacity = self
            .layout
            .cached_tree_updates
            .get(pending_batch_index)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?
            .len();
        let zkp_batch_index = usize::from(instruction_data.zkp_batch_index);
        if zkp_batch_index >= cached_tree_update_capacity {
            return Err(BatchedMerkleTreeError::CachedTreeUpdateIndexOutOfRange);
        }
        if u64::from(instruction_data.zkp_batch_index) >= num_full_zkp_batches {
            return Err(BatchedMerkleTreeError::HashChainNotReady);
        }

        let Some(zkp_batches_ahead) =
            u64::from(instruction_data.zkp_batch_index).checked_sub(num_inserted_zkp_batches)
        else {
            return Ok(None);
        };
        let next_index_for_proof = zkp_batches_ahead
            .checked_mul(zkp_batch_size)
            .and_then(|offset| self.next_index.checked_add(offset))
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;

        let already_cached = self
            .layout
            .cached_tree_updates
            .get(pending_batch_index)
            .ok_or(BatchedMerkleTreeError::CachedTreeUpdateIndexOutOfRange)?
            .get(zkp_batch_index)
            .map(|c| c.is_occupied())
            .unwrap_or(false);
        if already_cached {
            return Ok(None);
        }

        let leaves_hash_chain = *self
            .layout
            .hash_chains
            .get(pending_batch_index)
            .and_then(|chain| chain.data.get(zkp_batch_index))
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        let mut next_index_bytes = [0u8; 32];
        next_index_bytes[24..].copy_from_slice(next_index_for_proof.to_be_bytes().as_slice());
        let public_input_hash = create_hash_chain_from_array([
            instruction_data.old_root,
            instruction_data.new_root,
            leaves_hash_chain,
            next_index_bytes,
        ])?;

        Ok(Some(ReadyUpdate {
            zkp_batch_index,
            public_input_hash,
            old_root: instruction_data.old_root,
            new_root: instruction_data.new_root,
            compressed_proof: instruction_data.compressed_proof,
        }))
    }

    fn cache_ready_update(&mut self, update: &ReadyUpdate) -> Result<(), BatchedMerkleTreeError> {
        let pending_batch_index = self.queue_batches.pending_batch_index as usize;
        let slot = self
            .layout
            .cached_tree_updates
            .get_mut(pending_batch_index)
            .and_then(|u| u.get_mut(update.zkp_batch_index))
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        *slot = CachedTreeUpdate {
            old_root: update.old_root,
            new_root: update.new_root,
            occupied: 1,
        };
        Ok(())
    }

    /// Apply cached updates in order while each update's old root matches the
    /// account tree root, accumulating one cascade `BatchAddressAppendEvent`.
    /// Stops without error at the first update that is missing, unoccupied, or
    /// whose old root does not match.
    ///
    /// Steps (per applied zkp batch):
    /// 1. Read the pending zkp batch's cached update; stop if missing or empty.
    /// 2. Stop unless the update's old root matches the account tree root. The
    ///    proof was verified for the transition old_root -> new_root, so a match
    ///    means new_root is the correct next root for the current tree.
    /// 3. Apply: advance the tree next index and sequence number, append the new
    ///    root, and mark the zkp batch inserted.
    /// 4. Clear the applied cache slot.
    /// 5. Record the new root in the cascade event.
    #[cfg_attr(feature = "profile-program", light_program_profiler::profile)]
    fn apply_cached_tree_updates(
        &mut self,
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        let zkp_batch_size = self.queue_batches.zkp_batch_size;
        // One event covers the whole cascade: shared fields once, one root per
        // applied zkp batch. See `BatchAddressAppendEvent` for how the per-batch
        // values are derived from each root's position.
        let mut event: Option<BatchAddressAppendEvent> = None;
        loop {
            // 1. Read the pending zkp batch's cached update; stop if missing or
            //    empty.
            let pending_batch_index = self.queue_batches.pending_batch_index as usize;
            let zkp_batch_index = self
                .queue_batches
                .batches
                .get(pending_batch_index)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?
                .get_num_inserted_zkps() as usize;

            let cached_update = match self
                .layout
                .cached_tree_updates
                .get(pending_batch_index)
                .and_then(|updates| updates.get(zkp_batch_index))
            {
                Some(cached_update) if cached_update.is_occupied() => *cached_update,
                _ => return Ok(event),
            };

            // 2. Stop unless the update's old root matches the account tree root.
            //    old_root is a proof public input the prover chooses: a valid
            //    proof can attest to a transition from a starting root the
            //    account tree does not have. The leaves are fixed by the hash
            //    chain stored in the account and the StartIndex is computed from
            //    the slot, but the starting root is not. An update whose old_root
            //    does not match is evicted so a correct proof can be resubmitted
            //    (submit skips an occupied slot). The eviction must commit:
            //    returning an error would roll back the clear, so the slot is
            //    zeroed and the accumulated event returned.
            let current_root = self
                .get_root()
                .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
            if cached_update.old_root != current_root {
                self.clear_cached_tree_update(pending_batch_index, zkp_batch_index)?;
                #[cfg(feature = "log")]
                solana_msg::msg!(
                    "Evicted cached update [{}][{}]: old_root does not match account tree root",
                    pending_batch_index,
                    zkp_batch_index
                );
                return Ok(event);
            }

            // 3. Apply: advance the tree and mark the zkp batch inserted.
            self.check_tree_is_full(Some(zkp_batch_size))?;

            let old_next_index = self.next_index;
            self.increment_merkle_tree_next_index(zkp_batch_size);
            self.sequence_number += 1;
            self.append_root(cached_update.new_root);
            let root_index = self.get_root_index();

            let root_history_capacity = self.root_history_capacity;
            let sequence_number = self.sequence_number;
            let pending_batch_state = self
                .queue_batches
                .batches
                .get_mut(pending_batch_index)
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

            // 4. Clear the applied cache slot.
            self.clear_cached_tree_update(pending_batch_index, zkp_batch_index)?;

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
                first_zkp_batch_index: zkp_batch_index as u32,
                new_root: cached_update.new_root,
            });
            event.num_update += 1;
            event.new_root = cached_update.new_root;
        }
    }

    /// Reset the cached update at `[pending_batch_index][zkp_batch_index]` to empty (`occupied = 0`),
    /// freeing the slot for a fresh proof.
    fn clear_cached_tree_update(
        &mut self,
        pending_batch_index: usize,
        zkp_batch_index: usize,
    ) -> Result<(), BatchedMerkleTreeError> {
        let cached_update = self
            .layout
            .cached_tree_updates
            .get_mut(pending_batch_index)
            .and_then(|updates| updates.get_mut(zkp_batch_index))
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        *cached_update = CachedTreeUpdate::default();
        Ok(())
    }
}
