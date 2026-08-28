use std::{
    mem::size_of,
    ops::{Deref, DerefMut},
};

use super::batch::Batch;
#[cfg(all(not(target_os = "solana"), feature = "test-only"))]
use crate::nullifier_marker::host;
use crate::{
    batch::BatchState,
    constants::ADDRESS_TREE_INIT_ROOT_40,
    errors::{BatchedMerkleTreeError, MerkleTreeMetadataError},
    merkle_tree_metadata::{BatchedMerkleTreeMetadata, TreeType, ADDRESS_MERKLE_TREE_TYPE_V2},
    queue::insert_into_current_queue_batch,
    verify::CompressedProof,
    zero_copy::{
        TreeAccountLayout, ZeroCopyError, BOUNDED_CAPACITY, BOUNDED_LENGTH, CYCLIC_CAPACITY,
        CYCLIC_CURRENT_INDEX, CYCLIC_LENGTH,
    },
    BorshDeserialize, BorshSerialize,
};
use solana_address::Address as Pubkey;
use zolana_account_checks::{
    checks::check_account_info, discriminator::Discriminator, AccountView,
};
use zolana_hasher::primitives::is_canonical_bn254_scalar_be;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, BorshDeserialize, BorshSerialize)]
pub struct InstructionDataBatchNullifyInputs {
    pub new_root: [u8; 32],
    pub old_root: [u8; 32],
    pub zkp_batch_index: u16,
    pub compressed_proof: CompressedProof,
}

pub type InstructionDataAddressAppendInputs = InstructionDataBatchNullifyInputs;

pub type InstructionDataBatchAppendInputs = InstructionDataBatchNullifyInputs;

/// Batched Merkle tree zero copy account.
/// The account is used for batched state and address Merkle trees,
/// plus the input and address queues.
///
/// Tree roots can be used in zk proofs
/// outside of Light Protocol programs.
///
/// To access a tree root by index use:
/// - get_root_by_index
pub struct BatchedMerkleTreeAccount<'a, const RH: usize, const ZKP: usize> {
    pubkey: Pubkey,
    pub(crate) layout: &'a mut TreeAccountLayout<RH, ZKP>,
}

impl<const RH: usize, const ZKP: usize> Discriminator for BatchedMerkleTreeAccount<'_, RH, ZKP> {
    const LIGHT_DISCRIMINATOR: [u8; 8] = *b"BatchMta";
    const LIGHT_DISCRIMINATOR_SLICE: &'static [u8] = b"BatchMta";
}

impl<const RH: usize, const ZKP: usize> std::fmt::Debug for BatchedMerkleTreeAccount<'_, RH, ZKP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchedMerkleTreeAccount")
            .field("pubkey", &self.pubkey)
            .field("metadata", &self.layout.metadata)
            .finish()
    }
}

impl<const RH: usize, const ZKP: usize> PartialEq for BatchedMerkleTreeAccount<'_, RH, ZKP> {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
            && self.layout.discriminator == other.layout.discriminator
            && self.layout.metadata == other.layout.metadata
            && self.layout.root_history.header == other.layout.root_history.header
            && self.layout.root_history.data == other.layout.root_history.data
            && self
                .layout
                .hash_chains
                .iter()
                .zip(other.layout.hash_chains.iter())
                .all(|(a, b)| a.header == b.header && a.data == b.data)
    }
}

impl<'a, const RH: usize, const ZKP: usize> BatchedMerkleTreeAccount<'a, RH, ZKP> {
    /// Deserialize a batched address Merkle tree from account info.
    /// Should be used in solana programs.
    /// Checks that:
    /// 1. the account owner is `program_id`,
    /// 2. discriminator,
    /// 3. tree type is batched address tree type.
    pub fn address_from_account_info(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, ZKP>, BatchedMerkleTreeError> {
        Self::from_account_info::<ADDRESS_MERKLE_TREE_TYPE_V2>(program_id, account_info)
    }

    fn from_account_info<const TREE_TYPE: u64>(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, ZKP>, BatchedMerkleTreeError> {
        check_account_info::<Self>(program_id, account_info)?;
        let pubkey = *account_info.address();
        let mut data = account_info.try_borrow_mut()?;

        // Necessary to convince the borrow checker.
        let data_slice: &'a mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(data.as_mut_ptr(), data.len()) };
        Self::from_bytes::<TREE_TYPE>(data_slice, &pubkey)
    }

    /// Deserialize an address BatchedMerkleTreeAccount from bytes. Checks
    /// the discriminator and tree type. Available on both host and Solana
    /// SBF targets; callers that also need program-owner enforcement should
    /// use `address_from_account_info`.
    pub fn address_from_bytes(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, ZKP>, BatchedMerkleTreeError> {
        Self::from_bytes::<ADDRESS_MERKLE_TREE_TYPE_V2>(account_data, pubkey)
    }

    fn from_bytes<const TREE_TYPE: u64>(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, ZKP>, BatchedMerkleTreeError> {
        let layout: &'a mut TreeAccountLayout<RH, ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        if layout.metadata.tree_type != TREE_TYPE {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        Ok(BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
        root_history_capacity: u32,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        // Init root for indexed (`AddressV2`) trees. `None` uses the default
        // address sentinel root (`ADDRESS_TREE_INIT_ROOT_40`). Pass `Some` to
        // seed an indexed tree with a different sentinel, e.g. the BN254 `p-1`
        // nullifier-tree root (`NULLIFIER_TREE_INIT_ROOT_40`).
        address_init_root: Option<[u8; 32]>,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, ZKP>, BatchedMerkleTreeError> {
        if account_data.len() != size_of::<TreeAccountLayout<RH, ZKP>>() {
            return Err(ZeroCopyError::Size.into());
        }

        let layout: &'a mut TreeAccountLayout<RH, ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        Self::init_from_layout(
            layout,
            pubkey,
            root_history_capacity,
            input_queue_batch_size,
            input_queue_zkp_batch_size,
            height,
            tree_type,
            address_init_root,
        )
    }

    pub fn from_layout(
        pubkey: &Pubkey,
        layout: &'a mut TreeAccountLayout<RH, ZKP>,
    ) -> BatchedMerkleTreeAccount<'a, RH, ZKP> {
        BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init_from_layout(
        layout: &'a mut TreeAccountLayout<RH, ZKP>,
        pubkey: &Pubkey,
        root_history_capacity: u32,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        address_init_root: Option<[u8; 32]>,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, ZKP>, BatchedMerkleTreeError> {
        layout.discriminator = Self::LIGHT_DISCRIMINATOR;

        let account_metadata = &mut layout.metadata;

        account_metadata.root_history_capacity = root_history_capacity;
        account_metadata.height = height;
        account_metadata.tree_type = tree_type as u64;
        account_metadata.capacity = 2u64.pow(height);
        account_metadata.close_before_index = 0;
        account_metadata
            .queue_batches
            .init(input_queue_batch_size, input_queue_zkp_batch_size)?;

        // Root history is read from zero-initialized account memory.
        // Zeroed roots enable unified logic to zero out roots,
        // an unitialized root history vector would be an edge case.
        //
        // Initialize root history array with initial root.
        // Batch zkp updates require an input Merkle root.
        // The initial root is written at index 0 and the write head advanced to 1.
        let init_root = if tree_type == TreeType::AddressV2 {
            // Sanity check since init value is hardcoded.
            #[cfg(not(test))]
            if height != 40 {
                return Err(MerkleTreeMetadataError::InvalidHeight.into());
            }
            // The initialized indexed Merkle tree contains two elements.
            // 1. element:
            // H(0, 1, 452312848583266388373324160190187140051835877600158453279131187530910662655)
            // 2. element:
            // H(452312848583266388373324160190187140051835877600158453279131187530910662655, 0, 0)
            // ... other elements: 0
            layout.metadata.next_index = 1;
            // Initialized indexed Merkle tree root.
            // See https://github.com/helius-labs/privacy-program-libs/blob/c143c24f95c901e2eac96bc2bd498719958192cf/program-libs/indexed-merkle-tree/src/reference.rs#L69
            Some(address_init_root.unwrap_or(ADDRESS_TREE_INIT_ROOT_40))
        } else {
            None
        };
        // Root history is a cyclic ring buffer. Upstream fills the entire ring
        // (length == capacity) on init, then seeds the first root. Write the
        // cyclic header `[current_index, length, capacity]`: capacity and length
        // are both ROOT_HISTORY; current_index advances to 1 when a root is seeded.
        layout.root_history.header[CYCLIC_LENGTH] = RH as u64;
        layout.root_history.header[CYCLIC_CAPACITY] = RH as u64;
        layout.root_history.header[CYCLIC_CURRENT_INDEX] = 0;
        if let Some(root) = init_root {
            if let Some(slot) = layout.root_history.data.get_mut(0) {
                *slot = root;
            }
            layout.root_history.header[CYCLIC_CURRENT_INDEX] = 1;
        }
        // Bounded hash-chain regions: length 0, capacity ZKP.
        for hash_chain in layout.hash_chains.iter_mut() {
            hash_chain.header[BOUNDED_LENGTH] = 0;
            hash_chain.header[BOUNDED_CAPACITY] = ZKP as u64;
        }
        let next_index = layout.metadata.next_index;

        for (i, batches) in layout.metadata.queue_batches.batches.iter_mut().enumerate() {
            *batches = Batch::new(
                input_queue_batch_size,
                input_queue_zkp_batch_size,
                input_queue_batch_size * (i as u64) + next_index,
            );
        }

        #[cfg(all(not(target_os = "solana"), feature = "test-only"))]
        host::clear_tree(&pubkey.to_bytes());

        Ok(BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        })
    }

    pub fn insert_nullifier_into_queue(
        &mut self,
        nullifier: &[u8; 32],
    ) -> Result<u64, BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }
        if !is_canonical_bn254_scalar_be(nullifier) {
            return Err(BatchedMerkleTreeError::NonCanonicalFieldElement);
        }
        #[cfg(all(not(target_os = "solana"), feature = "test-only"))]
        if host::contains(&self.pubkey.to_bytes(), nullifier) {
            return Err(BatchedMerkleTreeError::NonInclusionCheckFailed);
        }

        let queue_index = self.queue_batches.next_index;
        let leaf_index = queue_index
            .checked_add(1)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)?;
        if leaf_index != self.next_queued_leaf_index()? {
            return Err(BatchedMerkleTreeError::QueueIndexMismatch);
        }
        self.check_queue_next_index_reached_tree_capacity()?;

        // When both batches filled while the forester was idle, the current
        // batch is the already-inserted batch about to be reused and the other
        // batch is Full. Its occupancy and the inserted batch's final root are
        // sufficient to mark it reclaimable here; requiring a successor tree update would
        // unnecessarily wedge all new spends at the rotation boundary.
        let current_batch_index = self.queue_batches.get_current_batch_index();
        if self.queue_batches.get_current_batch()?.checked_state()? == BatchState::Inserted {
            let successor_index = if current_batch_index == 0 { 1 } else { 0 };
            self.mark_previous_batch_reclaimable(successor_index)?;
        }

        let close_before_index = self.close_before_index;
        {
            let TreeAccountLayout {
                metadata,
                hash_chains,
                ..
            } = &mut *self.layout;
            let [hc0, hc1] = hash_chains;
            let mut hash_chain_stores = [hc0.view(), hc1.view()];
            insert_into_current_queue_batch(
                &mut metadata.queue_batches,
                &mut hash_chain_stores,
                nullifier,
                close_before_index,
            )?;
        }
        self.increment_queue_next_index();

        #[cfg(all(not(target_os = "solana"), feature = "test-only"))]
        host::reserve(&self.pubkey.to_bytes(), nullifier, queue_index);

        Ok(queue_index)
    }

    #[cfg(all(not(target_os = "solana"), feature = "test-only"))]
    pub fn close_nullifier_marker_host(
        &self,
        nullifier: &[u8; 32],
    ) -> Result<(), BatchedMerkleTreeError> {
        host::close(&self.pubkey.to_bytes(), nullifier, self.close_before_index)
    }

    /// Zero out roots corresponding to batch.sequence numbers > tree.sequence_number.
    /// The batch.sequence_number indicates when roots no longer contain values
    /// from the queue's previous batch, as they've been overwritten by newer updates.
    /// Root from the previous batch can prove inclusion of nullified values.
    /// Hence these roots must not exist once the batch's markers may be closed.
    ///
    /// Steps:
    /// 1. Check whether overlapping roots exist.
    /// 2. If yes:
    ///    2.1. Get, first safe root index.
    ///    2.2. Zero out roots from the oldest root to first safe root.
    ///
    /// Note on security for root buffer:
    /// Account {
    ///   batches: [B0, B1],
    ///     roots: [R0, R1, R2, R3, R4, R5, R6, R7, R8, R9],
    /// }
    ///
    /// Timeslot 0:
    /// - insert into B0 until full
    ///
    /// Timeslot 1:
    /// - insert into B1 until full
    /// - update tree with B0 in 4 partial updates, don't mark B0 reclaimable yet
    ///   -> R0 -> B0.1
    ///   -> R1 -> B0.2
    ///   -> R2 -> B0.3
    ///   -> R3 -> B0.4 - final B0 root
    ///   B0.sequence_number = 14 (4 + account.root.length)
    ///   B0.root_index = 3
    /// - execute some B1 root updates
    ///   -> R4 -> B1.1
    ///   -> R5 -> B1.2
    ///   -> R6 -> B1.3
    ///   -> R7 -> B1.4 - final B1 (update batch 0) root
    ///   B1.sequence_number = 18 (8 + account.root.length)
    ///   B1.root_index = 7
    ///   current_sequence_number = 8
    ///
    /// Timeslot 2:
    ///     - mark B0 reclaimable
    ///     - current_sequence_number < 14 -> zero out all roots until root index is 3
    ///     - R8 -> 0
    ///     - R9 -> 0
    ///     - R0 -> 0
    ///     - R1 -> 0
    ///     - R2 -> 0
    ///     - now all roots containing values nullified in the final B0 root update are zeroed
    ///     - B0 is safe to mark reclaimable
    ///
    fn zero_out_roots(&mut self, sequence_number: u64, first_safe_root_index: u32) {
        let TreeAccountLayout {
            metadata,
            root_history,
            ..
        } = &mut *self.layout;
        // 1. Check whether overlapping roots exist.
        let overlapping_roots_exits = sequence_number > metadata.sequence_number;
        if overlapping_roots_exits {
            let mut oldest_root_index = root_history.header[CYCLIC_CURRENT_INDEX] as usize;
            // 2.1. Get, num of remaining roots.
            //    Remaining roots have not been updated since
            //    the update of the previous batch therfore allow anyone to prove
            //    inclusion of values nullified in the previous batch.
            let num_remaining_roots = sequence_number - metadata.sequence_number;
            // 2.2. Zero out roots oldest to first safe root index.
            //      Skip one iteration we don't need to zero out
            //      the first safe root.
            for _ in 1..num_remaining_roots {
                if let Some(root) = root_history.data.get_mut(oldest_root_index) {
                    *root = [0u8; 32];
                }
                oldest_root_index += 1;
                oldest_root_index %= root_history.data.len();
            }
            // Defensive assert, it should never fail.
            assert_eq!(
                oldest_root_index, first_safe_root_index as usize,
                "Zeroing out roots failed."
            );
        }
    }

    pub(crate) fn mark_previous_batch_reclaimable(
        &mut self,
        successor_index: usize,
    ) -> Result<(), BatchedMerkleTreeError> {
        let half_batch = self.queue_batches.batch_size / 2;
        let close_before_index = self.close_before_index;
        let previous_index = if successor_index == 0 { 1 } else { 0 };

        let successor_is_half_full = self
            .queue_batches
            .batches
            .get(successor_index)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?
            .get_num_inserted_elements()
            >= half_batch;
        let previous = self
            .queue_batches
            .batches
            .get(previous_index)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
        let previous_is_inserted = previous.checked_state()? == BatchState::Inserted;
        if !successor_is_half_full
            || !previous_is_inserted
            || previous.is_reclaimable(close_before_index)
        {
            return Ok(());
        }

        let sequence_number = previous.sequence_number;
        let root_index = previous.root_index;
        let reclaimable_sequence = previous.reclaimable_sequence()?;
        self.zero_out_roots(sequence_number, root_index);
        self.close_before_index = close_before_index.max(reclaimable_sequence);
        Ok(())
    }

    fn latest_root_index(&self) -> usize {
        let capacity = self.layout.root_history.data.len();
        if capacity == 0 {
            return 0;
        }
        (self.layout.root_history.header[CYCLIC_CURRENT_INDEX] as usize + capacity - 1) % capacity
    }

    fn get_latest_root(&self) -> Option<&[u8; 32]> {
        self.layout.root_history.data.get(self.latest_root_index())
    }

    pub(crate) fn append_root(&mut self, root: [u8; 32]) {
        let capacity = self.layout.root_history.data.len();
        if capacity == 0 {
            return;
        }
        let current_index = self.layout.root_history.header[CYCLIC_CURRENT_INDEX] as usize;
        if let Some(slot) = self.layout.root_history.data.get_mut(current_index) {
            *slot = root;
        }
        self.layout.root_history.header[CYCLIC_CURRENT_INDEX] =
            ((current_index + 1) % capacity) as u64;
        // Cyclic vec length saturates at capacity once the ring is full. Upstream
        // init already fills length to capacity, so this is a no-op in practice
        // but keeps the header consistent if a fresh region is ever appended to.
        let len = self.layout.root_history.header[CYCLIC_LENGTH];
        if (len as usize) < capacity {
            self.layout.root_history.header[CYCLIC_LENGTH] = len + 1;
        }
    }

    /// Return the latest root index.
    pub fn get_root_index(&self) -> u32 {
        self.latest_root_index() as u32
    }

    /// Return the latest root of the tree.
    pub fn get_root(&self) -> Option<[u8; 32]> {
        self.get_latest_root().copied()
    }

    /// Return root from the root history by index.
    pub fn get_root_by_index(&self, index: usize) -> Option<&[u8; 32]> {
        self.layout.root_history.data.get(index)
    }

    /// Return the full root history.
    pub fn root_history(&self) -> &[[u8; 32]] {
        &self.layout.root_history.data
    }

    /// Return a stored queue hash-chain for a pending ZKP batch.
    pub fn get_hash_chain(&self, batch_index: usize, zkp_batch_index: usize) -> Option<[u8; 32]> {
        self.layout
            .hash_chains
            .get(batch_index)
            .and_then(|chain| chain.data.get(zkp_batch_index))
            .copied()
    }

    /// Return a reference to the metadata of the tree.
    pub fn get_metadata(&self) -> &BatchedMerkleTreeMetadata {
        &self.layout.metadata
    }

    /// Return a mutable reference to the metadata of the tree.
    pub fn get_metadata_mut(&mut self) -> &mut BatchedMerkleTreeMetadata {
        &mut self.layout.metadata
    }

    /// Checks if the tree is full, optionally for a batch size.
    /// A batch of `batch_size` values fits iff its last leaf index
    /// (`next_index + batch_size - 1`) is below `capacity`, i.e. the tree is
    /// full iff `next_index + batch_size > capacity`. Without a batch size,
    /// checks room for a single leaf.
    pub fn tree_is_full(&self, batch_size: Option<u64>) -> bool {
        self.next_index + batch_size.unwrap_or(1) > self.capacity
    }

    /// Checks that the next queued value still fits into the tree. Queued
    /// values are appended in queue order starting at the current batch's
    /// `start_index` (the init element occupies leaf 0, so queue sequence
    /// numbers are one behind tree leaf indices); the value fits iff that
    /// leaf index is below `capacity`.
    pub fn check_queue_next_index_reached_tree_capacity(
        &self,
    ) -> Result<(), BatchedMerkleTreeError> {
        let leaf_index = self.next_queued_leaf_index()?;
        if leaf_index >= self.capacity {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
    }

    /// Leaf index reserved by the next queue insertion. This includes values
    /// already queued but not yet applied to the Merkle tree. An `Inserted`
    /// current batch is about to be reused one rotation ahead, so its next
    /// leaf is `start_index + num_batches * batch_size`.
    pub fn next_queued_leaf_index(&self) -> Result<u64, BatchedMerkleTreeError> {
        let queue = &self.queue_batches;
        let current_batch = queue.get_current_batch()?;
        let offset = if current_batch.checked_state()? == BatchState::Inserted {
            queue.rotation()?
        } else {
            current_batch.get_num_inserted_elements()
        };
        current_batch
            .start_index
            .checked_add(offset)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)
    }

    /// Number of leaves not yet reserved by the queue.
    pub fn remaining_queue_capacity(&self) -> Result<u64, BatchedMerkleTreeError> {
        self.capacity
            .checked_sub(self.next_queued_leaf_index()?)
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)
    }

    /// Checks if the tree is full, optionally for a batch size.
    /// If batch_size is provided, checks if there is enough space for the batch.
    pub fn check_tree_is_full(
        &self,
        batch_size: Option<u64>,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.tree_is_full(batch_size) {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
    }

    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    pub(crate) fn increment_merkle_tree_next_index(&mut self, count: u64) {
        self.next_index += count;
    }

    fn increment_queue_next_index(&mut self) {
        self.queue_batches.next_index += 1;
    }
}

#[cfg(feature = "test-only")]
pub mod test_utils {
    use super::*;
    use zolana_event::BatchAddressAppendEvent;

    pub fn get_merkle_tree_account_size_default() -> usize {
        get_merkle_tree_account_size::<
            { crate::constants::ADDRESS_TREE_DEFAULT_RH },
            { crate::constants::ADDRESS_TREE_DEFAULT_ZKP },
        >()
    }

    impl<const RH: usize, const ZKP: usize> BatchedMerkleTreeAccount<'_, RH, ZKP> {
        pub fn apply_cached_tree_updates_unverified(
            &mut self,
        ) -> Result<Option<BatchAddressAppendEvent>, BatchedMerkleTreeError> {
            self.apply_cached_tree_updates()
        }
    }
}

impl<const RH: usize, const ZKP: usize> Deref for BatchedMerkleTreeAccount<'_, RH, ZKP> {
    type Target = BatchedMerkleTreeMetadata;

    fn deref(&self) -> &Self::Target {
        &self.layout.metadata
    }
}

impl<const RH: usize, const ZKP: usize> DerefMut for BatchedMerkleTreeAccount<'_, RH, ZKP> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.layout.metadata
    }
}

/// The Merkle tree account is a single zero-copy cast, so its size is fully
/// determined by the layout const generics.
pub fn get_merkle_tree_account_size<const RH: usize, const ZKP: usize>() -> usize {
    size_of::<TreeAccountLayout<RH, ZKP>>()
}

#[cfg(feature = "test-only")]
#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::{
        merkle_tree::test_utils::get_merkle_tree_account_size_default, zero_copy::CachedTreeUpdate,
    };

    fn random_nullifier(rng: &mut rand::prelude::StdRng) -> [u8; 32] {
        let mut value: [u8; 32] = rng.gen();
        value[0] = 0;
        value
    }

    #[test]
    fn test_from_bytes_invalid_tree_type() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size_default()];
        let account = BatchedMerkleTreeAccount::<200, 5>::from_bytes::<6>(
            &mut account_data,
            &Pubkey::default(),
        );
        assert_eq!(
            account.unwrap_err(),
            MerkleTreeMetadataError::InvalidTreeType.into()
        );
    }

    #[test]
    fn test_from_bytes_invalid_account_size() {
        let mut account_data = vec![0u8; 200];
        let account = BatchedMerkleTreeAccount::<200, 5>::from_bytes::<ADDRESS_MERKLE_TREE_TYPE_V2>(
            &mut account_data,
            &Pubkey::default(),
        );
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_init_invalid_account_size() {
        let mut account_data = vec![0u8; 200];
        let account = BatchedMerkleTreeAccount::<200, 5>::from_bytes::<ADDRESS_MERKLE_TREE_TYPE_V2>(
            &mut account_data,
            &Pubkey::default(),
        );
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_cached_tree_update_region_layout_and_size() {
        let update_size = core::mem::size_of::<crate::zero_copy::CachedTreeUpdate>();
        assert_eq!(update_size, 65);

        const RH: usize = 10;
        const ZKP: usize = 4;
        let full = get_merkle_tree_account_size::<RH, ZKP>();
        let cached_tree_update_bytes = core::mem::size_of::<[[CachedTreeUpdate; ZKP]; 2]>();
        assert_eq!(cached_tree_update_bytes, 2 * ZKP * update_size);

        let mut old_sized = vec![0u8; full - cached_tree_update_bytes];
        let account = BatchedMerkleTreeAccount::<RH, ZKP>::from_bytes::<ADDRESS_MERKLE_TREE_TYPE_V2>(
            &mut old_sized,
            &Pubkey::default(),
        );
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_state_struct_sizes() {
        assert_eq!(core::mem::size_of::<Batch>(), 72);
        assert_eq!(
            core::mem::size_of::<crate::queue_batch_metadata::QueueBatches>(),
            192
        );
        assert_eq!(core::mem::size_of::<BatchedMerkleTreeMetadata>(), 240);
    }

    /// Re-submitting a proof for a zkp batch that has already been applied
    /// (its StartIndex lies behind the account next index) is a no-op: the proof
    /// is not re-verified (an invalid proof still returns Ok) and no cached
    /// update is written.
    #[test]
    fn test_replay_after_apply_is_noop() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 4>()];
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<10, 4>::init(
            &mut account_data,
            &pubkey,
            10,
            4,
            1,
            40,
            TreeType::AddressV2,
            None,
        )
        .unwrap();

        // Two zkp batches finalized, one already inserted -> num_inserted = 1.
        {
            let batch = account.queue_batches.batches.get_mut(0).unwrap();
            batch.num_full_zkp_batches = 2;
            batch.advance_state_to_full().unwrap();
            batch.mark_as_inserted_in_merkle_tree(5, 0, 10).unwrap();
        }
        assert_eq!(
            account
                .queue_batches
                .batches
                .first()
                .unwrap()
                .get_num_inserted_zkps(),
            1
        );

        // Replay zkp batch 0, which is behind the live next index, with an
        // invalid proof. Verification must be skipped, so the call succeeds.
        let result = account
            .update_tree_from_address_queue(InstructionDataAddressAppendInputs {
                new_root: [3u8; 32],
                old_root: [2u8; 32],
                zkp_batch_index: 0,
                compressed_proof: CompressedProof::default(),
            })
            .unwrap();

        assert!(result.is_none());
        let cached_update = account
            .layout
            .cached_tree_updates
            .first()
            .and_then(|updates| updates.first())
            .unwrap();
        assert_eq!(cached_update.occupied, 0);
    }

    /// Re-submitting a proof for a zkp batch that is already cached (an occupied
    /// slot ahead of the inserted count) is verified like any other proof: an
    /// invalid proof is rejected and the existing cached update is preserved.
    #[test]
    fn test_replay_while_cached_verifies_and_keeps_update_on_failure() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 4>()];
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<10, 4>::init(
            &mut account_data,
            &pubkey,
            10,
            4,
            1,
            40,
            TreeType::AddressV2,
            None,
        )
        .unwrap();

        // Finalize a zkp batch so zkp_batch_index 0 passes the readiness guard.
        account
            .queue_batches
            .batches
            .get_mut(0)
            .unwrap()
            .num_full_zkp_batches = 2;

        // Cache an update at zkp batch 0 of a freshly initialized address tree.
        let cached = CachedTreeUpdate {
            old_root: [9u8; 32],
            new_root: [8u8; 32],
            occupied: 1,
        };
        *account
            .layout
            .cached_tree_updates
            .get_mut(0)
            .and_then(|updates| updates.get_mut(0))
            .unwrap() = cached;

        // Re-submit zkp batch 0 with different roots and an invalid proof. The
        // occupied slot is ahead of the inserted count, so the proof is verified
        // and rejected; the stored update is preserved unchanged.
        let result = account.update_tree_from_address_queue(InstructionDataAddressAppendInputs {
            new_root: [3u8; 32],
            old_root: [2u8; 32],
            zkp_batch_index: 0,
            compressed_proof: CompressedProof::default(),
        });

        assert!(matches!(
            result.unwrap_err(),
            BatchedMerkleTreeError::VerifierErrorError(_)
        ));
        let cached_update = account
            .layout
            .cached_tree_updates
            .first()
            .and_then(|updates| updates.first())
            .copied()
            .unwrap();
        assert_eq!(cached_update, cached);
    }

    /// Reclaimability trace with B = 4, Z = 1, RH = 10.
    /// `mark_previous_batch_reclaimable`
    /// is always called with the index of the batch whose update was applied
    /// (the pending index before the advance), never the post-advance index.
    /// 1. No batch is ready -> nothing should happen.
    /// 2. Batch 0 is inserted but Batch 1 is empty -> nothing should happen.
    /// 3. Batch 0 is inserted but Batch 1 is 25% full (not the required half)
    ///    -> nothing should happen.
    /// 4. Batch 0 is inserted and Batch 1 is half full
    ///    -> zero out all existing roots except the last one, w = 4.
    /// 5. Batch 1 is inserted and Batch 0 is empty
    ///    -> nothing should happen.
    /// 6. Batch 1 is inserted and Batch 0 is 25% full (not the required half)
    ///    -> nothing should happen.
    /// 7. Batch 1 is inserted and Batch 0 is half full and no overlapping roots exist
    ///    -> w = 8, roots are untouched.
    /// 8. Batch 1 is already reclaimable -> nothing should happen
    /// 9. Batch 0 is inserted and Batch 1 is full and overlapping roots exist
    ///    -> roots zeroed, w = 12.
    #[test]
    fn test_zero_out() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 4>()];
        let batch_size = 4;
        let zkp_batch_size = 1;
        let num_zkp_updates = batch_size / zkp_batch_size;
        let root_history_len = 10;
        let pubkey = Pubkey::new_unique();
        BatchedMerkleTreeAccount::<10, 4>::init(
            &mut account_data,
            &pubkey,
            root_history_len,
            batch_size,
            zkp_batch_size,
            40,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
        let mut latest_root_0 = [0u8; 32];
        let mut latest_root_1 = [0u8; 32];

        // 1. No batch is ready
        //   -> nothing should happen.
        {
            let mut account =
                insert_rnd_addresses::<10, 4>(&mut account_data, batch_size, rng, &pubkey).unwrap();

            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Full
            );
            // simulate batch insertion
            for _ in 0..num_zkp_updates {
                let rnd_root = rng.gen();
                account.append_root(rnd_root);
                latest_root_0 = rnd_root;
                account.layout.metadata.sequence_number += 1;
                let root_index = account.get_root_index();
                println!("root_index: {}", root_index);
                let sequence_number = account.sequence_number;

                let state = account.queue_batches.batches[0]
                    .mark_as_inserted_in_merkle_tree(sequence_number, root_index, root_history_len)
                    .unwrap();
                account
                    .queue_batches
                    .increment_pending_batch_index_if_inserted(state);
            }
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(account.queue_batches.pending_batch_index, 1);
            let index = account.queue_batches.batches[0].root_index;
            assert_eq!(
                account.layout.root_history.data[index as usize],
                latest_root_0
            );
            assert_eq!(account.close_before_index, 0);
        }
        // 2. Batch 0 is inserted but Batch 1 is not half full
        //    -> nothing should happen.
        {
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            account.mark_previous_batch_reclaimable(1).unwrap();
            assert_eq!(account_data, account_data_ref);
        }

        // 3. Batch 0 is inserted but Batch 1 is not half full
        //    -> nothing should happen.
        {
            // Make Batch 1 almost half full
            {
                insert_rnd_addresses::<10, 4>(&mut account_data, 1, rng, &pubkey).unwrap();
            }
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            account.mark_previous_batch_reclaimable(1).unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        // 4. Batch 0 is inserted and Batch 1 is half full
        //    -> should zero out all existing roots except the last one.
        {
            // Make Batch 1 half full
            {
                insert_rnd_addresses::<10, 4>(&mut account_data, 1, rng, &pubkey).unwrap();
            }
            let mut account_data = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            println!(
                "currently inserted elements: {:?}",
                account.queue_batches.batches[1].get_num_inserted_elements()
            );
            let previous_roots = account.layout.root_history.data.to_vec();
            account.mark_previous_batch_reclaimable(1).unwrap();
            let current_roots = account.layout.root_history.data.to_vec();
            println!("previous_roots: {:?}", previous_roots);
            assert_ne!(previous_roots, current_roots);
            let root_index = account.queue_batches.batches[0].root_index;
            assert_eq!(
                account.layout.root_history.data[root_index as usize],
                previous_roots[root_index as usize]
            );
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(account.queue_batches.batches[0].sequence_number, 14);
            assert_eq!(account.queue_batches.batches[0].root_index, 4);
            assert_eq!(account.close_before_index, 4);
            assert!(account.queue_batches.batches[0].is_reclaimable(account.close_before_index));
            assert_eq!(
                account.queue_batches.batches[0].get_num_inserted_zkps(),
                num_zkp_updates
            );

            for i in 0..root_history_len as usize {
                if i == root_index as usize {
                    assert_eq!(account.layout.root_history.data[i], latest_root_0);
                } else {
                    assert_eq!(account.layout.root_history.data[i], [0u8; 32]);
                }
            }
        }
        // Make Batch 1 full and insert
        {
            let mut account =
                insert_rnd_addresses::<10, 4>(&mut account_data, 2, rng, &pubkey).unwrap();

            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Full
            );
            // simulate batch insertion
            for _ in 0..num_zkp_updates {
                let rnd_root = rng.gen();
                account.append_root(rnd_root);
                latest_root_1 = rnd_root;
                account.layout.metadata.sequence_number += 1;
                let root_index = account.get_root_index();
                let sequence_number = account.sequence_number;

                let state = account.queue_batches.batches[1]
                    .mark_as_inserted_in_merkle_tree(sequence_number, root_index, root_history_len)
                    .unwrap();
                account
                    .queue_batches
                    .increment_pending_batch_index_if_inserted(state);
                account.mark_previous_batch_reclaimable(1).unwrap();
            }
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Inserted
            );
            assert_eq!(account.queue_batches.pending_batch_index, 0);
            let index = account.queue_batches.batches[1].root_index;
            assert_eq!(
                account.layout.root_history.data[index as usize],
                latest_root_1
            );
            assert_eq!(account.close_before_index, 4);
        }
        println!("pre 4");
        // 5. Batch 1 is inserted and Batch 0 is empty
        // -> nothing should happen
        {
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            for batch in account.queue_batches.batches.iter_mut() {
                println!("batch state: {:?}", batch);
            }
            account.mark_previous_batch_reclaimable(1).unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        println!("pre 5");
        let mut account =
            BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                .unwrap();
        for batch in account.queue_batches.batches.iter_mut() {
            println!("batch state: {:?}", batch);
        }
        // 6. Batch 1 is inserted and Batch 0 is almost half full
        // -> nothing should happen
        {
            // Make Batch 0 quater full
            {
                insert_rnd_addresses::<10, 4>(&mut account_data, 1, rng, &pubkey).unwrap();
            }
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            account.mark_previous_batch_reclaimable(0).unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        println!("pre 6");
        // 7. Batch 1 is inserted and Batch 0 is half full but no overlapping roots exist
        // -> batch 1 reclaimable, roots untouched
        {
            // Make Batch 0 half full
            {
                insert_rnd_addresses::<10, 4>(&mut account_data, 1, rng, &pubkey).unwrap();
            }
            // simulate 10 other batch insertions from an output queue
            {
                let mut account = BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(
                    &mut account_data,
                    &pubkey,
                )
                .unwrap();
                for _ in 0..10 {
                    let rnd_root = rng.gen();
                    account.append_root(rnd_root);
                    account.layout.metadata.sequence_number += 1;
                }
            }
            let mut account_data_ref = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            account.mark_previous_batch_reclaimable(0).unwrap();
            let mut account_ref = BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            account_ref.close_before_index = 8;
            assert_eq!(account.get_metadata(), account_ref.get_metadata());
            assert_eq!(account, account_ref);
        }
        // 8. Batch 1 is already reclaimable -> nothing should happen
        {
            let mut account_data_ref = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            account.mark_previous_batch_reclaimable(0).unwrap();
            let account_ref = BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            assert_eq!(account, account_ref);
        }
        // 9. Batch 0 is inserted and Batch 1 is full
        //    -> should mark Batch 0 reclaimable and zero overlapping roots
        {
            // Make Batch 0 and 1 full
            {
                insert_rnd_addresses::<10, 4>(&mut account_data, batch_size + 2, rng, &pubkey)
                    .unwrap();
            }
            // simulate batch 0 insertion
            {
                let mut account = BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(
                    &mut account_data,
                    &pubkey,
                )
                .unwrap();
                for _ in 0..num_zkp_updates {
                    let rnd_root = rng.gen();
                    account.append_root(rnd_root);
                    account.layout.metadata.sequence_number += 1;
                    let root_index = account.get_root_index();
                    let sequence_number = account.sequence_number;

                    let state = account.queue_batches.batches[0]
                        .mark_as_inserted_in_merkle_tree(
                            sequence_number,
                            root_index,
                            root_history_len,
                        )
                        .unwrap();
                    account
                        .queue_batches
                        .increment_pending_batch_index_if_inserted(state);
                }
            }
            println!("pre 9");
            let mut account_data_ref = account_data.clone();
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Full
            );
            account.mark_previous_batch_reclaimable(1).unwrap();
            let mut account_ref = BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            let root_index = account.queue_batches.batches[0].root_index;
            account_ref.close_before_index = 12;
            assert_eq!(account.get_metadata(), account_ref.get_metadata());
            for i in 0..root_history_len as usize {
                if i == root_index as usize {
                    continue;
                } else {
                    account_ref.layout.root_history.data[i] = [0u8; 32];
                }
            }
            assert_eq!(account, account_ref);
        }

        // simulate batch 1 insertion
        {
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            for _ in 0..num_zkp_updates {
                let rnd_root = rng.gen();
                account.append_root(rnd_root);
                account.layout.metadata.sequence_number += 1;
                let root_index = account.get_root_index();
                let sequence_number = account.sequence_number;

                let state = account.queue_batches.batches[1]
                    .mark_as_inserted_in_merkle_tree(sequence_number, root_index, root_history_len)
                    .unwrap();
                account
                    .queue_batches
                    .increment_pending_batch_index_if_inserted(state);
            }
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Inserted
            );
            assert_eq!(account.close_before_index, 12);
            assert!(account.queue_batches.batches[0].is_reclaimable(12));
            assert!(!account.queue_batches.batches[1].is_reclaimable(12));
        }
        println!("pre 9.1");

        // Reuse batch 1 with user tx
        {
            // fill batch 0
            {
                insert_rnd_addresses::<10, 4>(&mut account_data, batch_size, rng, &pubkey).unwrap();
            }
            println!("pre 9.2");
            // Reusing batch 1 marks it reclaimable from batch 0's full occupancy; no
            // additional batch-0 tree update is required.
            let mut account =
                BatchedMerkleTreeAccount::<10, 4>::address_from_bytes(&mut account_data, &pubkey)
                    .unwrap();
            let reclaimable_sequence = account.queue_batches.batches[1]
                .reclaimable_sequence()
                .unwrap();
            let address = random_nullifier(rng);
            assert_eq!(account.insert_nullifier_into_queue(&address).unwrap(), 20);
            assert_eq!(account.close_before_index, reclaimable_sequence);
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Fill
            );
        }
    }

    fn insert_rnd_addresses<'a, const RH: usize, const ZKP: usize>(
        account_data: &'a mut [u8],
        batch_size: u64,
        rng: &mut rand::prelude::StdRng,
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, ZKP>, BatchedMerkleTreeError> {
        let mut account =
            BatchedMerkleTreeAccount::<RH, ZKP>::address_from_bytes(account_data, pubkey).unwrap();
        for i in 0..batch_size {
            println!("inserting address: {}", i);
            let address = random_nullifier(rng);
            account.insert_nullifier_into_queue(&address)?;
        }
        Ok(account)
    }

    #[test]
    fn test_check_queue_next_index_reached_tree_capacity() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 200>()];
        let batch_size = 200;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 4;
        let tree_capacity = 2u64.pow(height);
        let pubkey = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<10, 200>::init(
            &mut account_data,
            &pubkey,
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        // 1. empty tree is not full
        assert!(account
            .check_queue_next_index_reached_tree_capacity()
            .is_ok());

        let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
        // The init element occupies leaf 0, so only capacity - 1 values fit.
        let account =
            insert_rnd_addresses::<10, 200>(&mut account_data, tree_capacity - 2, rng, &pubkey)
                .unwrap();
        // 2. one free leaf left: not full
        assert!(account
            .check_queue_next_index_reached_tree_capacity()
            .is_ok());
        // 3. the last value fills the last leaf: full
        let mut account =
            insert_rnd_addresses::<10, 200>(&mut account_data, 1, rng, &pubkey).unwrap();
        assert_eq!(
            account
                .check_queue_next_index_reached_tree_capacity()
                .unwrap_err(),
            BatchedMerkleTreeError::TreeIsFull
        );
        // 4. one more value does not fit and must be rejected.
        assert_eq!(
            account
                .insert_nullifier_into_queue(&random_nullifier(rng))
                .unwrap_err(),
            BatchedMerkleTreeError::TreeIsFull
        );
    }

    #[test]
    fn test_tree_is_full() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 4;
        let mut account = BatchedMerkleTreeAccount::<10, 5>::init(
            &mut account_data,
            &Pubkey::new_unique(),
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        // 1. empty tree is not full
        assert!(!account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_ok());
        assert!(!account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_ok());
        account.next_index = account.capacity - 2;
        assert!(!account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_ok());
        assert!(!account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_ok());
        // A batch of 2 fills the last two leaves exactly: not full.
        assert!(!account.tree_is_full(Some(2)));
        assert!(account.check_tree_is_full(Some(2)).is_ok());
        // A batch of 3 would write past the last leaf: full.
        assert!(account.tree_is_full(Some(3)));
        assert!(account.check_tree_is_full(Some(3)).is_err());
        account.next_index = account.capacity - 1;
        assert!(!account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_ok());
        // The final leaf still fits a single value (or a batch of 1).
        assert!(!account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_ok());
        assert!(account.tree_is_full(Some(2)));
        assert!(account.check_tree_is_full(Some(2)).is_err());
        account.next_index = account.capacity;
        assert!(account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_err());
        assert!(account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_err());
        account.next_index = account.capacity + 1;
        assert!(account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_err());
        assert!(account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_err());
    }
    #[test]
    fn test_increment_next_index() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<10, 5>::init(
            &mut account_data,
            &pubkey,
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        let previous_next_index = account.next_index;
        let previous_queue_next_index = account.queue_batches.next_index;
        account.increment_merkle_tree_next_index(10);
        assert_eq!(account.next_index, previous_next_index + 10);
        assert_eq!(account.queue_batches.next_index, previous_queue_next_index);
        let previous_next_index = account.next_index;
        let previous_queue_next_index = account.queue_batches.next_index;
        account.increment_queue_next_index();
        assert_eq!(account.next_index, previous_next_index);
        assert_eq!(
            account.queue_batches.next_index,
            previous_queue_next_index + 1
        );
    }

    #[test]
    fn test_get_pubkey() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<10, 5>::init(
            &mut account_data,
            &pubkey,
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        assert_eq!(*account.pubkey(), pubkey);
    }
}
