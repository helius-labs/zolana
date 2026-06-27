use std::{
    mem::size_of,
    ops::{Deref, DerefMut},
};

use solana_address::Address as Pubkey;
use zolana_account_checks::{
    checks::check_account_info, discriminator::Discriminator, AccountView,
};
use zolana_hasher::hash_to_field_size::hash_to_bn254_field_size_be;
use zolana_merkle_tree_metadata::{
    errors::MerkleTreeMetadataError, merkle_tree::MerkleTreeMetadata, TreeType,
    ADDRESS_MERKLE_TREE_TYPE_V2,
};

use super::batch::Batch;
use crate::{
    batch::BatchState,
    constants::ADDRESS_TREE_INIT_ROOT_40,
    errors::BatchedMerkleTreeError,
    merkle_tree_metadata::BatchedMerkleTreeMetadata,
    queue::insert_into_current_queue_batch,
    verify::CompressedProof,
    zero_copy::{
        TreeAccountLayout, ZeroCopyError, BOUNDED_CAPACITY, BOUNDED_LENGTH, CYCLIC_CAPACITY,
        CYCLIC_CURRENT_INDEX, CYCLIC_LENGTH,
    },
    BorshDeserialize, BorshSerialize,
};

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
pub struct BatchedMerkleTreeAccount<
    'a,
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
> {
    pubkey: Pubkey,
    pub(crate) layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>,
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> Discriminator
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    const LIGHT_DISCRIMINATOR: [u8; 8] = *b"BatchMta";
    const LIGHT_DISCRIMINATOR_SLICE: &'static [u8] = b"BatchMta";
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> std::fmt::Debug
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchedMerkleTreeAccount")
            .field("pubkey", &self.pubkey)
            .field("metadata", &self.layout.metadata)
            .finish()
    }
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> PartialEq
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
            && self.layout.discriminator == other.layout.discriminator
            && self.layout.metadata == other.layout.metadata
            && self.layout.root_history.header == other.layout.root_history.header
            && self.layout.root_history.data == other.layout.root_history.data
            && self.layout.bloom_filters == other.layout.bloom_filters
            && self
                .layout
                .hash_chains
                .iter()
                .zip(other.layout.hash_chains.iter())
                .all(|(a, b)| a.header == b.header && a.data == b.data)
    }
}

impl<'a, const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize>
    BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>
{
    /// Deserialize a batched address Merkle tree from account info.
    /// Should be used in solana programs.
    /// Checks that:
    /// 1. the account owner is `program_id`,
    /// 2. discriminator,
    /// 3. tree type is batched address tree type.
    pub fn address_from_account_info(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        Self::from_account_info::<ADDRESS_MERKLE_TREE_TYPE_V2>(program_id, account_info)
    }

    fn from_account_info<const TREE_TYPE: u64>(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
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
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        Self::from_bytes::<ADDRESS_MERKLE_TREE_TYPE_V2>(account_data, pubkey)
    }

    fn from_bytes<const TREE_TYPE: u64>(
        account_data: &'a mut [u8],
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        let layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP> =
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
        metadata: MerkleTreeMetadata,
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
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        if account_data.len() != size_of::<TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>>() {
            return Err(ZeroCopyError::Size.into());
        }

        let layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        Self::init_from_layout(
            layout,
            pubkey,
            metadata,
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
        layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>,
    ) -> BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP> {
        BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init_from_layout(
        layout: &'a mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>,
        pubkey: &Pubkey,
        metadata: MerkleTreeMetadata,
        root_history_capacity: u32,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType,
        address_init_root: Option<[u8; 32]>,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        layout.discriminator = Self::LIGHT_DISCRIMINATOR;

        let account_metadata = &mut layout.metadata;

        // Precompute Merkle tree pubkey hash for use in system program.
        // The compressed account hash depends on the Merkle tree pubkey and leaf index.
        // Poseidon hashes required input size < bn254 field size.
        // To map 256bit pubkeys to < 254bit field size, we hash Pubkeys
        // and truncate the hash to 31 bytes/248 bits.
        account_metadata.hashed_pubkey = hash_to_bn254_field_size_be(&pubkey.to_bytes());
        account_metadata.metadata = metadata;
        account_metadata.root_history_capacity = root_history_capacity;
        account_metadata.height = height;
        account_metadata.tree_type = tree_type as u64;
        account_metadata.capacity = 2u64.pow(height);
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
        for update_vec in layout.cached_tree_updates.iter_mut() {
            update_vec.header[BOUNDED_LENGTH] = 0;
            update_vec.header[BOUNDED_CAPACITY] = ZKP as u64;
        }
        let next_index = layout.metadata.next_index;

        // Bloom-filter parameters upstream stores in the queue/batch metadata so
        // that indexers parsing our account with the upstream crate size the
        // bloom region (`bloom_filter_capacity / 8` bytes) correctly and
        // reconstruct the same bloom filters. Capacity is in bits.
        let bloom_filter_capacity_bits = (BLOOM as u64) * 8;
        layout.metadata.queue_batches.bloom_filter_capacity = bloom_filter_capacity_bits;

        for (i, batches) in layout.metadata.queue_batches.batches.iter_mut().enumerate() {
            *batches = Batch::new(
                input_queue_batch_size,
                input_queue_zkp_batch_size,
                input_queue_batch_size * (i as u64) + next_index,
            );
            batches.set_bloom_filter_params(NUM_ITERS as u64, bloom_filter_capacity_bits);
        }

        Ok(BatchedMerkleTreeAccount {
            pubkey: *pubkey,
            layout,
        })
    }

    pub fn insert_address_into_queue(
        &mut self,
        address: &[u8; 32],
        current_slot: &u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.tree_type != TreeType::AddressV2 as u64 {
            return Err(MerkleTreeMetadataError::InvalidTreeType.into());
        }

        // Ensure that all elements that are inserted into the queue
        // can be inserted into the tree.
        self.check_queue_next_index_reached_tree_capacity()?;

        {
            let TreeAccountLayout {
                metadata,
                bloom_filters,
                hash_chains,
                ..
            } = &mut *self.layout;
            let [hc0, hc1] = hash_chains;
            let mut hash_chain_stores = [hc0.view(), hc1.view()];
            insert_into_current_queue_batch(
                &mut metadata.queue_batches,
                bloom_filters,
                &mut hash_chain_stores,
                address,
                address,
                current_slot,
            )?;
        }
        self.increment_queue_next_index();
        Ok(())
    }

    /// Zero out roots corresponding to batch.sequence numbers > tree.sequence_number.
    /// The batch.sequence_number indicates when roots no longer contain values
    /// from the queue's previous batch, as they've been overwritten by newer updates.
    /// Root from the previous batch can prove inclusion of nullified values.
    /// Hence these roots must not exists after the bloom filter has been zeroed.
    ///
    /// Steps:
    /// 1. Check whether overlapping roots exist.
    /// 2. If yes:
    ///    2.1. Get, first safe root index.
    ///    2.2. Zero out roots from the oldest root to first safe root.
    ///
    /// Note on security for root buffer:
    /// Account {
    ///   bloom_filter: [B0, B1],
    ///     roots: [R0, R1, R2, R3, R4, R5, R6, R7, R8, R9],
    /// }
    ///
    /// Timeslot 0:
    /// - insert into B0 until full
    ///
    /// Timeslot 1:
    /// - insert into B1 until full
    /// - update tree with B0 in 4 partial updates, don't clear B0 yet
    ///   -> R0 -> B0.1
    ///   -> R1 -> B0.2
    ///   -> R2 -> B0.3
    ///   -> R3 -> B0.4 - final B0 root
    ///   B0.sequence_number = 13 (3 + account.root.length)
    ///   B0.root_index = 3
    /// - execute some B1 root updates
    ///   -> R4 -> B1.1
    ///   -> R5 -> B1.2
    ///   -> R6 -> B1.3
    ///   -> R7 -> B1.4 - final B1 (update batch 0) root
    ///   B0.sequence_number = 17 (7 + account.root.length)
    ///   B0.root_index = 7
    ///   current_sequence_number = 8
    ///
    /// Timeslot 2:
    ///     - clear B0
    ///     - current_sequence_number < 14 -> zero out all roots until root index is 3
    ///     - R8 -> 0
    ///     - R9 -> 0
    ///     - R0 -> 0
    ///     - R1 -> 0
    ///     - R2 -> 0
    ///     - now all roots containing values nullified in the final B0 root update are zeroed
    ///     - B0 is safe to clear
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

    /// Zero out bloom filter of previous batch if 50% of the
    /// current batch has been processed.
    ///
    /// Idea:
    /// 1. Zeroing out the bloom filter of the previous batch is expensive
    ///    -> the forester should do it.
    /// 2. We don't want to zero out the bloom filter when inserting
    ///    the last zkp of a batch for this might result in failing user tx.
    /// 3. Wait until next batch is 50% full as grace period for clients
    ///    to switch from proof by index to proof by zkp
    ///    for values inserted in the previous batch.
    ///
    /// Steps:
    /// 1. Previous batch must be inserted and bloom filter must not be zeroed out.
    /// 2. Current batch must be 50% full
    /// 3. if yes
    ///    3.1. mark bloom filter as zeroed
    ///    3.2. zero out bloom filter
    ///    3.3. zero out roots if needed
    ///
    ///   Initial state: 0 pending -> 1 previous pending even though it was never used
    ///   0 inserted -> 1 pending 0 -> 1 pending 50% - zero out 0 -> 1 inserted
    ///   0 pending -> 1 inserted
    pub(crate) fn zero_out_previous_batch_bloom_filter(
        &mut self,
    ) -> Result<(), BatchedMerkleTreeError> {
        let current_batch = self.queue_batches.pending_batch_index as usize;
        let batch_size = self.queue_batches.batch_size;
        let previous_pending_batch_index = if 0 == current_batch { 1 } else { 0 };
        let current_batch_is_half_full = {
            let current = self
                .queue_batches
                .batches
                .get(current_batch)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            let current_batch_is_not_inserted = current.get_state() != BatchState::Inserted;
            let num_inserted_elements = current.get_num_inserted_elements();
            let current_batch_is_half_full = num_inserted_elements >= batch_size / 2;
            current_batch_is_half_full && current_batch_is_not_inserted
        };

        let previous_pending_batch = self
            .queue_batches
            .batches
            .get_mut(previous_pending_batch_index)
            .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;

        let previous_batch_is_inserted = previous_pending_batch.get_state() == BatchState::Inserted;
        let previous_batch_is_ready =
            previous_batch_is_inserted && !previous_pending_batch.bloom_filter_is_zeroed();

        // Current batch is at least half full, previous batch is inserted, and not zeroed.
        if current_batch_is_half_full && previous_batch_is_ready {
            // 3.1. Mark bloom filter zeroed.
            previous_pending_batch.set_bloom_filter_to_zeroed();
            let seq = previous_pending_batch.sequence_number;
            let root_index = previous_pending_batch.root_index;
            // 3.2. Zero out bloom filter.
            {
                let bloom_filter = self
                    .layout
                    .bloom_filters
                    .get_mut(previous_pending_batch_index)
                    .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
                bloom_filter.zero();
            }
            // 3.3. Zero out roots if a root exists in root history
            // which allows to prove inclusion of a value
            // that was inserted into the bloom filter just zeroed out.
            {
                self.zero_out_roots(seq, root_index);
            }
        }

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

    /// Check non-inclusion in all bloom filters
    /// which are not zeroed.
    pub fn check_input_queue_non_inclusion(
        &mut self,
        value: &[u8; 32],
    ) -> Result<(), BatchedMerkleTreeError> {
        let TreeAccountLayout {
            metadata,
            bloom_filters,
            ..
        } = &mut *self.layout;
        for i in 0..metadata.queue_batches.num_batches as usize {
            let bloom_filter = bloom_filters
                .get(i)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?;
            Batch::check_non_inclusion(value, bloom_filter)?;
        }
        Ok(())
    }

    /// Checks if the tree is full, optionally for a batch size.
    /// If batch_size is provided, checks if there is enough space for the batch.
    pub fn tree_is_full(&self, batch_size: Option<u64>) -> bool {
        self.next_index + batch_size.unwrap_or_default() >= self.capacity
    }

    pub fn check_queue_next_index_reached_tree_capacity(
        &self,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.queue_batches.next_index >= self.capacity {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
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

    pub fn get_associated_queue(&self) -> &Pubkey {
        &self.layout.metadata.metadata.associated_queue
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

    pub fn get_merkle_tree_account_size_default() -> usize {
        get_merkle_tree_account_size::<
            { crate::constants::ADDRESS_TREE_DEFAULT_RH },
            { crate::constants::ADDRESS_TREE_DEFAULT_NUM_ITERS },
            { crate::constants::ADDRESS_TREE_DEFAULT_BLOOM },
            { crate::constants::ADDRESS_TREE_DEFAULT_ZKP },
        >()
    }
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> Deref
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    type Target = BatchedMerkleTreeMetadata;

    fn deref(&self) -> &Self::Target {
        &self.layout.metadata
    }
}

impl<const RH: usize, const NUM_ITERS: usize, const BLOOM: usize, const ZKP: usize> DerefMut
    for BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.layout.metadata
    }
}

/// The Merkle tree account is a single zero-copy cast, so its size is fully
/// determined by the layout const generics.
pub fn get_merkle_tree_account_size<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>() -> usize {
    size_of::<TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>>()
}

#[cfg(feature = "test-only")]
#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::{
        merkle_tree::test_utils::get_merkle_tree_account_size_default, zero_copy::CachedTreeUpdate,
    };

    #[test]
    fn test_from_bytes_invalid_tree_type() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size_default()];
        let account = BatchedMerkleTreeAccount::<200, 3, 20000, 5>::from_bytes::<6>(
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
        let account = BatchedMerkleTreeAccount::<200, 3, 20000, 5>::from_bytes::<
            ADDRESS_MERKLE_TREE_TYPE_V2,
        >(&mut account_data, &Pubkey::default());
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_init_invalid_account_size() {
        let mut account_data = vec![0u8; 200];
        let account = BatchedMerkleTreeAccount::<200, 3, 20000, 5>::from_bytes::<
            ADDRESS_MERKLE_TREE_TYPE_V2,
        >(&mut account_data, &Pubkey::default());
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    #[test]
    fn test_cached_tree_update_region_layout_and_size() {
        let update_size = core::mem::size_of::<crate::zero_copy::CachedTreeUpdate>();
        assert_eq!(update_size, 65);
        // The vec has a [u64; 2] header, so its size is the header plus the
        // updates rounded up to the 8-byte header alignment.
        assert_eq!(
            core::mem::size_of::<crate::zero_copy::CachedTreeUpdateVec<5>>(),
            (16 + 5 * update_size).next_multiple_of(8)
        );

        const RH: usize = 10;
        const NI: usize = 3;
        const BLOOM: usize = 1000;
        const ZKP: usize = 4;
        let full = get_merkle_tree_account_size::<RH, NI, BLOOM, ZKP>();
        let cached_tree_update_bytes =
            2 * core::mem::size_of::<crate::zero_copy::CachedTreeUpdateVec<ZKP>>();
        assert_eq!(
            cached_tree_update_bytes,
            2 * (16 + ZKP * update_size).next_multiple_of(8)
        );

        let mut old_sized = vec![0u8; full - cached_tree_update_bytes];
        let account = BatchedMerkleTreeAccount::<RH, NI, BLOOM, ZKP>::from_bytes::<
            ADDRESS_MERKLE_TREE_TYPE_V2,
        >(&mut old_sized, &Pubkey::default());
        assert!(matches!(
            account.unwrap_err(),
            crate::errors::BatchedMerkleTreeError::ZeroCopy(ZeroCopyError::Size)
        ));
    }

    /// Re-submitting a proof for a zkp batch that has already been applied
    /// (its StartIndex lies behind the account next index) is a no-op: the proof
    /// is not re-verified (an invalid proof still returns Ok) and no cached
    /// update is written.
    #[test]
    fn test_replay_after_apply_is_noop() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 4>()];
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
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
            .and_then(|chain| chain.data.first())
            .unwrap();
        assert_eq!(cached_update.occupied, 0);
    }

    /// Re-submitting a proof for a zkp batch that is already cached (an occupied
    /// slot with the same StartIndex is present) is a no-op: the proof is not
    /// re-verified and the existing update is not overwritten.
    #[test]
    fn test_replay_while_cached_is_noop() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 4>()];
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
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
        // Re-submitting the same slot is rejected as already cached, so submit
        // returns false and apply never runs; the update stays in place.
        let cached = CachedTreeUpdate {
            old_root: [9u8; 32],
            new_root: [8u8; 32],
            occupied: 1,
        };
        *account
            .layout
            .cached_tree_updates
            .get_mut(0)
            .and_then(|chain| chain.data.get_mut(0))
            .unwrap() = cached;

        // Re-submit zkp batch 0 with different roots and an invalid proof.
        // The cached StartIndex matches, so submit is skipped (no verification)
        // and the stored update is preserved unchanged.
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
            .and_then(|chain| chain.data.first())
            .copied()
            .unwrap();
        assert_eq!(cached_update, cached);
    }

    /// 1. No batch is ready -> nothing should happen.
    /// 2. Batch 0 is inserted but Batch 1 is empty -> nothing should happen.
    /// 3. Batch 0 is inserted but Batch 1 is 25% full (not the required half)
    ///    -> nothing should happen.
    /// 4. Batch 0 is inserted and Batch 1 is full
    ///    -> should zero out all existing roots except the last one.
    /// 5. Batch 1 is inserted and Batch 0 is empty
    ///    -> nothing should happen.
    /// 6. Batch 1 is inserted and Batch 0 is 25% full (not the required half)
    ///    -> nothing should happen.
    /// 7. Batch 1 is inserted and Batch 0 is half full and no overlapping roots exist
    ///    -> bloom filter is zeroed, roots are untouched.
    /// 8. Batch 1 is already zeroed -> nothing should happen
    /// 9. Batch 1 is inserted and Batch 0 is full and overlapping roots exist
    #[test]
    fn test_zero_out() {
        let current_slot = 1;
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 4>()];
        let batch_size = 4;
        let zkp_batch_size = 1;
        let num_zkp_updates = batch_size / zkp_batch_size;
        let root_history_len = 10;
        let pubkey = Pubkey::new_unique();
        BatchedMerkleTreeAccount::<10, 3, 1000, 4>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
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
            let mut account = insert_rnd_addresses::<10, 3, 1000, 4>(
                &mut account_data,
                batch_size,
                rng,
                current_slot,
                &pubkey,
            )
            .unwrap();

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
        }
        // 2. Batch 0 is inserted but Batch 1 is not half full
        //    -> nothing should happen.
        {
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }

        // 3. Batch 0 is inserted but Batch 1 is not half full
        //    -> nothing should happen.
        {
            // Make Batch 1 almost half full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        // 4. Batch 0 is inserted and Batch 1 is half full
        //    -> should zero out all existing roots except the last one.
        {
            // Make Batch 1 half full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            let mut account_data = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            println!(
                "currently inserted elements: {:?}",
                account.queue_batches.batches[1].get_num_inserted_elements()
            );
            let previous_roots = account.layout.root_history.data.to_vec();
            account.zero_out_previous_batch_bloom_filter().unwrap();
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
            assert!(account.queue_batches.batches[0].bloom_filter_is_zeroed());
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
            let mut account = insert_rnd_addresses::<10, 3, 1000, 4>(
                &mut account_data,
                2,
                rng,
                current_slot,
                &pubkey,
            )
            .unwrap();

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
                account.zero_out_previous_batch_bloom_filter().unwrap();
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
        }
        println!("pre 4");
        // 5. Batch 1 is inserted and Batch 0 is empty
        // -> nothing should happen
        {
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            for batch in account.queue_batches.batches.iter_mut() {
                println!("batch state: {:?}", batch);
            }
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        println!("pre 5");
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
            &mut account_data,
            &pubkey,
        )
        .unwrap();
        for batch in account.queue_batches.batches.iter_mut() {
            println!("batch state: {:?}", batch);
        }
        // 6. Batch 1 is inserted and Batch 0 is almost half full
        // -> nothing should happen
        {
            // Make Batch 0 quater full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            let mut account_data = account_data.clone();
            let account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            assert_eq!(account_data, account_data_ref);
        }
        println!("pre 6");
        // 7. Batch 1 is inserted and Batch 0 is half full but no overlapping roots exist
        // -> bloom filter zeroed, roots untouched
        {
            // Make Batch 0 half full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    1,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            // simulate 10 other batch insertions from an output queue
            {
                let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
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
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            let mut account_ref = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            account_ref.layout.bloom_filters[1].zero();
            account_ref.queue_batches.batches[1].set_bloom_filter_to_zeroed();
            assert_eq!(account.get_metadata(), account_ref.get_metadata());
            assert_eq!(account, account_ref);
        }
        // 8. Batch 1 is already zeroed -> nothing should happen
        {
            let mut account_data_ref = account_data.clone();
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            account.zero_out_previous_batch_bloom_filter().unwrap();
            let account_ref = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            assert_eq!(account, account_ref);
        }
        // 9. Batch 0 is inserted and Batch 1 is full
        //    -> should zero out Batch 0s bloom filter and overlapping roots
        {
            // Make Batch 0 and 1 full
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    batch_size + 2,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            // simulate batch 0 insertion
            {
                let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
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
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            assert_eq!(
                account.queue_batches.batches[0].get_state(),
                BatchState::Inserted
            );
            assert_eq!(
                account.queue_batches.batches[1].get_state(),
                BatchState::Full
            );
            account.zero_out_previous_batch_bloom_filter().unwrap();
            let mut account_ref = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data_ref,
                &pubkey,
            )
            .unwrap();
            let root_index = account.queue_batches.batches[0].root_index;
            account_ref.layout.bloom_filters[0].zero();
            account_ref.queue_batches.batches[0].set_bloom_filter_to_zeroed();
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
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
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
            assert!(account.layout.bloom_filters[0].is_zeroed());
            assert!(!account.layout.bloom_filters[1].is_zeroed());
        }
        println!("pre 9.1");

        // Zero out batch 1 with user tx
        {
            // fill batch 0
            {
                insert_rnd_addresses::<10, 3, 1000, 4>(
                    &mut account_data,
                    batch_size,
                    rng,
                    current_slot,
                    &pubkey,
                )
                .unwrap();
            }
            println!("pre 9.2");
            // the insertion into batch 1 fails since the bloom filter of batch 0 is not zeroed out.
            let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 4>::address_from_bytes(
                &mut account_data,
                &pubkey,
            )
            .unwrap();
            let address = rng.gen();
            let result = account.insert_address_into_queue(&address, &current_slot);
            assert_eq!(
                result.unwrap_err(),
                BatchedMerkleTreeError::BloomFilterNotZeroed
            );
        }
    }

    fn insert_rnd_addresses<
        'a,
        const RH: usize,
        const NUM_ITERS: usize,
        const BLOOM: usize,
        const ZKP: usize,
    >(
        account_data: &'a mut [u8],
        batch_size: u64,
        rng: &mut rand::prelude::StdRng,
        current_slot: u64,
        pubkey: &Pubkey,
    ) -> Result<BatchedMerkleTreeAccount<'a, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError>
    {
        let mut account =
            BatchedMerkleTreeAccount::<RH, NUM_ITERS, BLOOM, ZKP>::address_from_bytes(
                account_data,
                pubkey,
            )
            .unwrap();
        for i in 0..batch_size {
            println!("inserting address: {}", i);
            let address = rng.gen();
            account.insert_address_into_queue(&address, &current_slot)?;
        }
        Ok(account)
    }

    #[test]
    fn test_check_queue_next_index_reached_tree_capacity() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 200>()];
        let batch_size = 200;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let current_slot = 1;
        let height = 4;
        let tree_capacity = 2u64.pow(height);
        let pubkey = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<10, 3, 1000, 200>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
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
        let account = insert_rnd_addresses::<10, 3, 1000, 200>(
            &mut account_data,
            tree_capacity - 1,
            rng,
            current_slot,
            &pubkey,
        )
        .unwrap();
        // 2. tree at capacity - 1 is not full
        assert!(account
            .check_queue_next_index_reached_tree_capacity()
            .is_ok());
        // 3. tree at capacity is full
        let account = insert_rnd_addresses::<10, 3, 1000, 200>(
            &mut account_data,
            1,
            rng,
            current_slot,
            &pubkey,
        )
        .unwrap();
        assert_eq!(
            account
                .check_queue_next_index_reached_tree_capacity()
                .unwrap_err(),
            BatchedMerkleTreeError::TreeIsFull
        );
    }

    #[test]
    fn test_check_non_inclusion() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let mut current_slot = 1;
        let height = 40;
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &Pubkey::new_unique(),
            MerkleTreeMetadata::default(),
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

        let mut inserted_elements = vec![];
        let rng = &mut rand::rngs::StdRng::from_seed([0u8; 32]);
        // fill batch 0
        for _ in 0..batch_size {
            let address = rng.gen();
            inserted_elements.push(address);
            account
                .insert_address_into_queue(&address, &current_slot)
                .unwrap();
            assert_eq!(
                account.queue_batches.batches[0].start_slot, 1,
                "Slot should not change unless batch is advanced from inserted to fill."
            );
            current_slot += 1;
        }
        // 1. Non inclusion of inserted elements should fail
        for address in inserted_elements.iter() {
            assert_eq!(
                account
                    .check_input_queue_non_inclusion(address)
                    .unwrap_err(),
                BatchedMerkleTreeError::NonInclusionCheckFailed
            );
        }
        // 2. Non inclusion of random address should pass
        for _ in 0..100 {
            let address = rng.gen();
            account.check_input_queue_non_inclusion(&address).unwrap();
        }
        // fill batch 1
        for _ in 0..batch_size {
            current_slot += 1;
            let address = rng.gen();
            inserted_elements.push(address);
            account
                .insert_address_into_queue(&address, &current_slot)
                .unwrap();
        }
        // 3. Non inclusion of inserted elements should fail
        for address in inserted_elements.iter() {
            assert_eq!(
                account
                    .check_input_queue_non_inclusion(address)
                    .unwrap_err(),
                BatchedMerkleTreeError::NonInclusionCheckFailed
            );
        }
        // clear bloom filter 0
        account.layout.bloom_filters[0].zero();
        // 4. Non inclusion of batch 0 inserted elements should pass
        for address in inserted_elements.iter().take(batch_size as usize) {
            account.check_input_queue_non_inclusion(address).unwrap();
        }
        // 5. Non inclusion of batch 1 inserted elements should fail
        for address in inserted_elements[batch_size as usize..].iter() {
            assert_eq!(
                account
                    .check_input_queue_non_inclusion(address)
                    .unwrap_err(),
                BatchedMerkleTreeError::NonInclusionCheckFailed
            );
        }
        // clear bloom filter 1
        account.layout.bloom_filters[1].zero();
        // 6. Non inclusion of batch 0 inserted elements should pass
        for address in inserted_elements.iter() {
            account.check_input_queue_non_inclusion(address).unwrap();
        }
    }

    #[test]
    fn test_tree_is_full() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 4;
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &Pubkey::new_unique(),
            MerkleTreeMetadata::default(),
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
        account.next_index = account.capacity - 1;
        assert!(!account.tree_is_full(None));
        assert!(account.check_tree_is_full(None).is_ok());
        assert!(account.tree_is_full(Some(1)));
        assert!(account.check_tree_is_full(Some(1)).is_err());
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
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let mut account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata::default(),
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
    fn test_get_pubkey_and_associated_queue() {
        let mut account_data = vec![0u8; get_merkle_tree_account_size::<10, 3, 1000, 5>()];
        let batch_size = 5;
        let zkp_batch_size = 1;
        let root_history_len = 10;
        let height = 40;
        let pubkey = Pubkey::new_unique();
        let associated_queue = Pubkey::new_unique();
        let account = BatchedMerkleTreeAccount::<10, 3, 1000, 5>::init(
            &mut account_data,
            &pubkey,
            MerkleTreeMetadata {
                associated_queue,
                ..MerkleTreeMetadata::default()
            },
            root_history_len,
            batch_size,
            zkp_batch_size,
            height,
            TreeType::AddressV2,
            None,
        )
        .unwrap();
        assert_eq!(*account.pubkey(), pubkey);
        assert_eq!(*account.get_associated_queue(), associated_queue);
    }
}
