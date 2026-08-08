use zolana_hasher::hash_chain::create_hash_chain_from_array;

use crate::{
    errors::{BatchedMerkleTreeError, MerkleTreeMetadataError},
    events::BatchAddressAppendEvent,
    merkle_tree::{
        BatchedMerkleTreeAccount, FoldedAddressAppendInputs, InstructionDataAddressAppendInputs,
    },
    merkle_tree_metadata::TreeType,
    verify::{verify_batch_address_fold, verify_batch_address_update},
    zero_copy::CachedTreeUpdate,
};

/// `Some` selects prepared-operand verification. Both modes bind the same
/// public-input hash to the same verifying key. Uninhabited when the feature
/// is off, so only `None` exists there.
#[cfg(feature = "vk-registry")]
type VerifyMode<'a> = Option<&'a groth16_solana::groth16::PreparedVkRefs<'a>>;
#[cfg(not(feature = "vk-registry"))]
type VerifyMode<'a> = Option<&'a core::convert::Infallible>;

impl<'a, const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize>
    BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>
{
    /// Verify one address-append proof and apply every now-applicable cached
    /// update.
    ///
    /// A replayed proof caches nothing and returns `None`. Cached updates that
    /// do not match the account tree root are skipped, not errors.
    pub fn update_tree_from_address_queue(
        &mut self,
        instruction_data: InstructionDataAddressAppendInputs,
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        self.update_tree_from_address_queue_inner(instruction_data, None)
    }

    /// [`Self::update_tree_from_address_queue`] with prepared registry refs
    /// the caller authenticated for this tree's batch size.
    #[cfg(feature = "vk-registry")]
    pub fn update_tree_from_address_queue_registered(
        &mut self,
        instruction_data: InstructionDataAddressAppendInputs,
        refs: &groth16_solana::groth16::PreparedVkRefs,
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        self.update_tree_from_address_queue_inner(instruction_data, Some(refs))
    }

    fn update_tree_from_address_queue_inner(
        &mut self,
        instruction_data: InstructionDataAddressAppendInputs,
        verify_mode: VerifyMode<'_>,
    ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        if !self.verify_proof_cache_update(&instruction_data, verify_mode)? {
            return Ok(None);
        }
        self.apply_cached_tree_updates()
    }

    /// Verify one folded proof and apply a whole run of address appends.
    ///
    /// # Root history
    ///
    /// A fold advances the tree by `run` zkp batches but appends exactly ONE
    /// root. The intermediate roots are private to the fold proof and never
    /// enter `root_history`.
    ///
    /// That is sound because those roots never existed on chain, so no client
    /// could have bound a proof to one. It is nonetheless a real difference
    /// from submitting the run as `run` separate transactions, where every
    /// intermediate root lands in history. Anything that assumes one history
    /// entry per zkp batch must read `num_update` on the event instead of
    /// counting roots.
    ///
    /// The fold applies only at the head. The run must be finalized and start at
    /// the pending zkp batch, so StartIndex is the tree's current next index and
    /// not a caller-supplied offset. `old_root` must equal the account tree root,
    /// checked before verifying so a span from another tree state costs no
    /// pairing.
    pub fn update_tree_from_address_queue_folded(
        &mut self,
        instruction_data: &FoldedAddressAppendInputs,
        run: u32,
    ) -> Result<BatchAddressAppendEvent, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        if run < 2 {
            return Err(BatchedMerkleTreeError::FoldedRunTooShort);
        }

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

        // More inserted than full means the batch counters disagree, which is
        // account corruption rather than a run the forester sent too early.
        let available = num_full_zkp_batches
            .checked_sub(num_inserted_zkp_batches)
            .ok_or(BatchedMerkleTreeError::InvalidBatchState)?;
        if u64::from(run) > available {
            return Err(BatchedMerkleTreeError::FoldedRunNotReady);
        }

        let current_root = self
            .get_root()
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        if instruction_data.old_root != current_root {
            return Err(BatchedMerkleTreeError::FoldedSpanRootMismatch);
        }

        // Every leg's element chain comes from account state, so the caller cannot
        // choose which elements the span claims to have appended.
        let first_zkp_batch = usize::try_from(num_inserted_zkp_batches)
            .map_err(|_| BatchedMerkleTreeError::ArithmeticOverflow)?;
        let chains = self
            .layout
            .hash_chains
            .get(pending_batch_index)
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
        let mut elements = [0u8; 32];
        for offset in 0..run as usize {
            let leg = *chains
                .data
                .get(first_zkp_batch + offset)
                .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
            elements = if offset == 0 {
                leg
            } else {
                create_hash_chain_from_array([elements, leg])?
            };
        }
        let mut start_index_bytes = [0u8; 32];
        start_index_bytes[24..].copy_from_slice(self.next_index.to_be_bytes().as_slice());
        let public_input_hash = create_hash_chain_from_array([
            instruction_data.old_root,
            instruction_data.new_root,
            elements,
            start_index_bytes,
        ])?;
        verify_batch_address_fold(
            self.height,
            zkp_batch_size,
            run,
            public_input_hash,
            &instruction_data.proof,
        )?;

        let span = u64::from(run)
            .checked_mul(zkp_batch_size)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
        self.check_tree_is_full(Some(span))?;

        let old_next_index = self.next_index;
        let start_sequence_number = self.sequence_number;
        let next_sequence_number = self
            .sequence_number
            .checked_add(1)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
        self.increment_merkle_tree_next_index(span);
        self.sequence_number = next_sequence_number;
        self.append_root(instruction_data.new_root);
        let root_index = self.get_root_index();

        let root_history_capacity = self.root_history_capacity;
        let sequence_number = self.sequence_number;
        for _ in 0..run {
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
        }
        self.zero_out_previous_batch_bloom_filter()?;

        // A forester may already have proved some of these slots one by one.
        // The fold applied them, so an occupied slot left behind would cost a
        // wasted transaction once the index cycles back to it.
        for offset in 0..run as usize {
            let zkp_batch_index = first_zkp_batch
                .checked_add(offset)
                .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
            self.clear_cached_tree_update(pending_batch_index, zkp_batch_index)?;
        }

        Ok(BatchAddressAppendEvent {
            merkle_tree_pubkey: self.pubkey().to_bytes(),
            zkp_batch_size: u16::try_from(zkp_batch_size)
                .map_err(|_| BatchedMerkleTreeError::ArithmeticOverflow)?,
            old_next_index,
            start_sequence_number,
            first_root_index: root_index,
            num_update: run,
            first_zkp_batch_index: u32::try_from(first_zkp_batch)
                .map_err(|_| BatchedMerkleTreeError::ArithmeticOverflow)?,
            new_root: instruction_data.new_root,
        })
    }

    /// Verify one address-append proof and cache the update at its zkp batch
    /// index. Returns `true` when a new update was cached, or `false` when the
    /// update is already applied (its zkp batch index is behind the number of
    /// inserted zkp batches) or already cached (an occupied slot at this
    /// StartIndex exists). A replayed proof is then a no-op.
    fn verify_proof_cache_update(
        &mut self,
        instruction_data: &InstructionDataAddressAppendInputs,
        verify_mode: VerifyMode<'_>,
    ) -> Result<bool, BatchedMerkleTreeError> {
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
            return Ok(false);
        };
        // Reconstruct the proof's StartIndex: the tree next index this zkp
        // batch writes at.
        let next_index_for_proof = zkp_batches_ahead
            .checked_mul(zkp_batch_size)
            .and_then(|offset| self.next_index.checked_add(offset))
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;

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
        match verify_mode {
            None => verify_batch_address_update(
                zkp_batch_size,
                public_input_hash,
                &instruction_data.compressed_proof,
            )?,
            #[cfg(feature = "vk-registry")]
            Some(refs) => crate::verify::verify_batch_address_update_registered(
                zkp_batch_size,
                public_input_hash,
                &instruction_data.compressed_proof,
                refs,
            )?,
            #[cfg(not(feature = "vk-registry"))]
            Some(never) => match *never {},
        }

        // old_root is the prover's public input. Apply checks it against the account
        // tree root before applying.
        let cached_update = self
            .layout
            .cached_tree_updates
            .get_mut(pending_batch_index)
            .and_then(|updates| updates.get_mut(zkp_batch_index))
            .ok_or(BatchedMerkleTreeError::InvalidIndex)?;
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

            // old_root is a proof public input the prover chooses, so a valid proof
            // can attest to a transition from a starting root the account tree does
            // not have. The leaves are fixed by the hash chain stored in the account
            // and the StartIndex is computed from the slot, but the starting root is
            // not. An update whose old_root does not match is evicted so a correct
            // proof can be resubmitted (submit skips an occupied slot). The eviction
            // must commit. Returning an error would roll back the clear, so the slot
            // is zeroed and the accumulated event returned.
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

            self.check_tree_is_full(Some(zkp_batch_size))?;

            let old_next_index = self.next_index;
            self.increment_merkle_tree_next_index(zkp_batch_size);
            self.sequence_number = self
                .sequence_number
                .checked_add(1)
                .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
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

            self.clear_cached_tree_update(pending_batch_index, zkp_batch_index)?;

            // The first applied zkp batch fixes the shared event fields. Later
            // batches only advance the count and the final root. Intermediate roots
            // live in root_history.
            let event_zkp_batch_size = u16::try_from(zkp_batch_size)
                .map_err(|_| BatchedMerkleTreeError::ArithmeticOverflow)?;
            let event_zkp_batch_index = u32::try_from(zkp_batch_index)
                .map_err(|_| BatchedMerkleTreeError::ArithmeticOverflow)?;
            let event = event.get_or_insert_with(|| BatchAddressAppendEvent {
                merkle_tree_pubkey: self.pubkey().to_bytes(),
                zkp_batch_size: event_zkp_batch_size,
                old_next_index,
                start_sequence_number: sequence_number,
                first_root_index: root_index,
                num_update: 0,
                first_zkp_batch_index: event_zkp_batch_index,
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
