use zolana_hasher::hash_chain::create_hash_chain_from_array;

use crate::{
    batch::BatchState,
    errors::NullifierTreeError,
    layout::{CachedTreeUpdate, NullifierTreeLayout, TreeType},
    verify::{verify_batch_address_update, CompressedProof},
    BorshDeserialize, BorshSerialize,
};
use zolana_event::BatchAddressAppendEvent;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, BorshDeserialize, BorshSerialize)]
pub struct InstructionDataBatchNullifyInputs {
    pub new_root: [u8; 32],
    pub old_root: [u8; 32],
    pub zkp_batch_index: u16,
    pub compressed_proof: CompressedProof,
}

pub type InstructionDataAddressAppendInputs = InstructionDataBatchNullifyInputs;

impl CachedTreeUpdate {
    fn is_occupied(&self) -> bool {
        self.occupied != 0
    }
}

impl<const ZKP: usize> NullifierTreeLayout<ZKP> {
    /// Verify one address-append proof and apply every now-applicable cached
    /// update.
    ///
    /// Steps:
    /// 1. Reject non-address trees.
    /// 2. Verify the proof and cache the update. A replayed proof caches
    ///    nothing, so the apply pass is skipped and an empty result returned.
    /// 3. Apply cached updates in order: the just-verified one and any it
    ///    unblocks. Updates that do not match the account tree are skipped, not
    ///    errors.
    pub fn update_tree_from_address_queue(
        &mut self,
        merkle_tree_pubkey: [u8; 32],
        instruction_data: InstructionDataAddressAppendInputs,
    ) -> Result<Option<BatchAddressAppendEvent>, NullifierTreeError> {
        // 1. Reject non-address trees.
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(NullifierTreeError::InvalidTreeType);
        }
        // 2. Verify the proof and cache the update.
        if !self.verify_proof_cache_update(&instruction_data)? {
            return Ok(None);
        }
        // 3. Apply cached updates in order.
        self.apply_cached_tree_updates(merkle_tree_pubkey)
    }

    /// Verify one address-append proof and cache the update at its zkp batch
    /// index. Returns `true` when a new update was cached, or `false` when the
    /// update is already applied (its zkp batch index is behind the number of
    /// inserted zkp batches) or already cached (an occupied slot at this
    /// StartIndex exists); a replayed proof is then a no-op.
    ///
    /// Steps:
    /// 1. Validate the zkp batch index and that its hash chain is finalized.
    /// 2. Return `false` if the update is already applied, then reconstruct the
    ///    proof's StartIndex, the tree next index this zkp batch writes at.
    /// 3. Rebuild the public input hash and verify the proof.
    /// 4. Store the cached update, keyed by StartIndex, at its zkp batch index.
    fn verify_proof_cache_update(
        &mut self,
        instruction_data: &InstructionDataAddressAppendInputs,
    ) -> Result<bool, NullifierTreeError> {
        let zkp_batch_size = self.queue_batches.zkp_batch_size;
        let pending_batch_index = self.queue_batches.pending_batch_index as usize;

        let (num_full_zkp_batches, num_inserted_zkp_batches) = {
            let batch = self
                .queue_batches
                .batches
                .get(pending_batch_index)
                .ok_or(NullifierTreeError::InvalidBatchIndex)?;
            (batch.num_full_zkp_batches, batch.get_num_inserted_zkps())
        };

        // 1. Validate the zkp batch index and that its hash chain is finalized.
        let cached_tree_update_capacity = self
            .cached_tree_updates
            .get(pending_batch_index)
            .ok_or(NullifierTreeError::InvalidBatchIndex)?
            .len();
        let zkp_batch_index = usize::from(instruction_data.zkp_batch_index);
        if zkp_batch_index >= cached_tree_update_capacity {
            return Err(NullifierTreeError::CachedTreeUpdateIndexOutOfRange);
        }
        if u64::from(instruction_data.zkp_batch_index) >= num_full_zkp_batches {
            return Err(NullifierTreeError::HashChainNotReady);
        }

        // 2. Skip when already applied: a zkp batch index behind the number of
        //    inserted zkp batches belongs to an update that is already in the
        //    tree, so a replayed proof is a no-op.
        let Some(zkp_batches_ahead) =
            u64::from(instruction_data.zkp_batch_index).checked_sub(num_inserted_zkp_batches)
        else {
            return Ok(false);
        };
        // Reconstruct the proof's StartIndex: the tree next index this zkp
        // batch writes at.
        let next_index_for_proof = zkp_batches_ahead
            .checked_mul(zkp_batch_size)
            .and_then(|offset| self.next_index.checked_add(offset))
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;

        // 3. Rebuild the public input hash and verify the proof.
        let leaves_hash_chain = self
            .get_hash_chain(pending_batch_index, zkp_batch_index)
            .ok_or(NullifierTreeError::InvalidIndex)?;
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

        // 4. Store the cached update at its zkp batch index. old_root is the
        //    prover's public input; apply checks it against the account tree
        //    root before applying.
        let cached_update = self
            .cached_tree_updates
            .get_mut(pending_batch_index)
            .and_then(|updates| updates.get_mut(zkp_batch_index))
            .ok_or(NullifierTreeError::InvalidIndex)?;
        *cached_update = CachedTreeUpdate {
            old_root: instruction_data.old_root,
            new_root: instruction_data.new_root,
            occupied: 1,
        };
        Ok(true)
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
    ///    root, and mark the ZKP batch inserted. When that fully inserts the
    ///    pending batch, advance the nullifier PDA-close watermark before advancing
    ///    the pending index (spec batch append steps 8-9).
    /// 4. Clear the applied cache slot.
    /// 5. Record the new root in the cascade event.
    #[cfg_attr(feature = "profile-program", light_program_profiler::profile)]
    pub fn apply_cached_tree_updates(
        &mut self,
        merkle_tree_pubkey: [u8; 32],
    ) -> Result<Option<BatchAddressAppendEvent>, NullifierTreeError> {
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
                .ok_or(NullifierTreeError::InvalidBatchIndex)?
                .get_num_inserted_zkps() as usize;

            let cached_update = match self
                .cached_tree_updates
                .get(pending_batch_index)
                .and_then(|updates| updates.get(zkp_batch_index))
            {
                Some(cached_update) if cached_update.is_occupied() => *cached_update,
                _ => break Ok(event),
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
            let current_root = self.get_root().ok_or(NullifierTreeError::InvalidIndex)?;
            if cached_update.old_root != current_root {
                self.clear_cached_tree_update(pending_batch_index, zkp_batch_index)?;
                #[cfg(feature = "log")]
                solana_msg::msg!(
                    "Evicted cached update [{}][{}]: old_root does not match account tree root",
                    pending_batch_index,
                    zkp_batch_index
                );
                break Ok(event);
            }

            // 3. Apply: advance the tree and mark the zkp batch inserted.
            self.check_tree_is_full(zkp_batch_size)?;

            let old_next_index = self.next_index;
            self.increment_merkle_tree_next_index(zkp_batch_size);
            self.sequence_number += 1;
            self.append_root(cached_update.new_root)?;
            let root_index = self.get_root_index();

            let sequence_number = self.sequence_number;
            let pending_batch_state = self
                .queue_batches
                .batches
                .get_mut(pending_batch_index)
                .ok_or(NullifierTreeError::InvalidBatchIndex)?
                .mark_as_inserted_in_merkle_tree()?;
            self.advance_nullifier_pda_close_watermark(pending_batch_state)?;
            self.queue_batches
                .increment_pending_batch_index_if_inserted(pending_batch_state);

            // 4. Clear the applied cache slot.
            self.clear_cached_tree_update(pending_batch_index, zkp_batch_index)?;

            // 5. Record this root in the cascade event. The first applied zkp
            //    batch fixes the shared fields; later batches only advance the
            //    count and the final root (intermediate roots live in
            //    root_history).
            let event = event.get_or_insert(BatchAddressAppendEvent {
                merkle_tree_pubkey,
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

    /// Advances the nullifier PDA-close watermark when the pending batch becomes fully
    /// inserted. This must run before `pending_batch_index` advances so it still
    /// identifies the updated batch.
    ///
    /// A fully inserted batch has written exactly one root-history window, so
    /// every accepted root now contains every value queued before that batch.
    /// This depends only on the inserted batch's start index: the preceding
    /// batch may already have been reused and returned to `Fill`.
    fn advance_nullifier_pda_close_watermark(
        &mut self,
        pending_batch_state: BatchState,
    ) -> Result<(), NullifierTreeError> {
        if pending_batch_state != BatchState::Inserted {
            return Ok(());
        }

        let pending_batch = self
            .queue_batches
            .batches
            .get(self.queue_batches.pending_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)?;
        self.close_before_index = self.close_before_index.max(
            pending_batch
                .start_index
                .checked_sub(1)
                .ok_or(NullifierTreeError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    /// Reset the cached update at `[pending_batch_index][zkp_batch_index]` to empty (`occupied = 0`),
    /// freeing the slot for a fresh proof.
    fn clear_cached_tree_update(
        &mut self,
        pending_batch_index: usize,
        zkp_batch_index: usize,
    ) -> Result<(), NullifierTreeError> {
        let cached_update = self
            .cached_tree_updates
            .get_mut(pending_batch_index)
            .and_then(|updates| updates.get_mut(zkp_batch_index))
            .ok_or(NullifierTreeError::InvalidIndex)?;
        *cached_update = CachedTreeUpdate::default();
        Ok(())
    }

    fn append_root(&mut self, root: [u8; 32]) -> Result<(), NullifierTreeError> {
        let current_index = self.root_history.current_index as usize;
        let capacity = self.root_history.roots.len();
        let slot = self
            .root_history
            .roots
            .get_mut(current_index)
            .ok_or(NullifierTreeError::InvalidRootHistoryCapacity)?;
        *slot = root;
        self.root_history.current_index = ((current_index + 1) % capacity) as u64;
        Ok(())
    }

    /// Checks whether `num_leaves` values fit in the remaining tree capacity.
    fn check_tree_is_full(&self, num_leaves: u64) -> Result<(), NullifierTreeError> {
        if self.tree_is_full(num_leaves) {
            return Err(NullifierTreeError::TreeIsFull);
        }
        Ok(())
    }

    fn increment_merkle_tree_next_index(&mut self, count: u64) {
        self.next_index += count;
    }
}
