use std::{
    mem::size_of,
    ops::{Deref, DerefMut},
};

use crate::zero_copy::{QueueAccountLayout, ZeroCopyError};
use aligned_sized::aligned_sized;
use light_account_checks::{checks::check_account_info, discriminator::Discriminator, AccountView};
use light_bloom_filter::BloomFilter;
use light_hasher::hash_to_field_size::hash_to_bn254_field_size_be;
use light_merkle_tree_metadata::{
    errors::MerkleTreeMetadataError, queue::QueueMetadata, QueueType, OUTPUT_STATE_QUEUE_TYPE_V2,
};
use solana_address::Address as Pubkey;

// Import the feature-gated types from lib.rs
use super::batch::BatchState;
use crate::{
    batch::Batch, constants::NUM_BATCHES, errors::BatchedMerkleTreeError,
    queue_batch_metadata::QueueBatches, BorshDeserialize, BorshSerialize,
};

#[repr(C)]
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Debug,
    PartialEq,
    Default,
    Clone,
    Copy,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
#[aligned_sized(anchor)]
pub struct BatchedQueueMetadata {
    pub metadata: QueueMetadata,
    pub batch_metadata: QueueBatches,
    /// Maximum number of leaves that can fit in the tree, calculated as 2^height.
    /// For example, a tree with height 3 can hold up to 8 leaves.
    pub tree_capacity: u64,
    pub hashed_merkle_tree_pubkey: [u8; 32],
    pub hashed_queue_pubkey: [u8; 32],
}

impl BatchedQueueMetadata {
    pub fn init(
        &mut self,
        meta_data: QueueMetadata,
        batch_size: u64,
        zkp_batch_size: u64,
        queue_pubkey: &Pubkey,
        tree_capacity: u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        self.metadata = meta_data;
        self.batch_metadata.init(batch_size, zkp_batch_size)?;
        for (i, batches) in self.batch_metadata.batches.iter_mut().enumerate() {
            *batches = Batch::new(batch_size, zkp_batch_size, batch_size * (i as u64));
        }

        // Set tree capacity for overflow checks
        self.tree_capacity = tree_capacity;

        // Precompute Merkle tree pubkey hash for use in system program.
        // The compressed account hash depends on the Merkle tree pubkey and leaf index.
        // Poseidon hashes required input size < bn254 field size.
        // To map 256bit pubkeys to < 254bit field size, we hash Pubkeys
        // and truncate the hash to 31 bytes/248 bits.
        self.hashed_merkle_tree_pubkey =
            hash_to_bn254_field_size_be(&meta_data.associated_merkle_tree.to_bytes());
        self.hashed_queue_pubkey = hash_to_bn254_field_size_be(&queue_pubkey.to_bytes());
        Ok(())
    }
}

/// Batched queue zero copy account.
/// Used for output queues that batch account hashes.
/// Output queues store compressed account hashes,
/// to be appended to the associated batched Merkle tree
/// in batches with a zero-knowledge proof (zkp),
/// ie. it stores hashes and commits these to hash chains.
/// Each hash chain is used as public input for
/// a batch append zkp.
///
/// An output queue is configured with:
/// 1. 2 batches
/// 2. 2 value vecs (one for each batch)
///    value vec length = batch size
/// 3. 2 hash chain vecs (one for each batch)
///    hash chain store length = batch size /zkp batch size
///
/// Default config:
/// - 50,000 batch size
/// - 500 zkp batch size
///
/// Initialization:
/// - an output queue is initialized
///   in combination with a state Merkle tree
/// - `init_batched_state_merkle_tree_from_account_info`
///
/// For deserialization use:
/// - in program:   `output_from_account_info`
/// - in client:    `output_from_bytes`
///
/// To insert a value, callers use:
/// - `insert_into_current_batch`
///
/// A compressed account can be spent or read
/// while in the output queue.
///
/// To spend, callers use:
/// - check_leaf_index_could_exist_in_batches in combination with
///   `prove_inclusion_by_index_and_zero_out_leaf`
///
/// To read, callers use:
/// - `prove_inclusion_by_index`
pub struct BatchedQueueAccount<'a, const BATCH: usize, const ZKP: usize> {
    pubkey: Pubkey,
    pub(crate) layout: &'a mut QueueAccountLayout<BATCH, ZKP>,
}

impl<const BATCH: usize, const ZKP: usize> Discriminator for BatchedQueueAccount<'_, BATCH, ZKP> {
    const LIGHT_DISCRIMINATOR: [u8; 8] = *b"queueacc";
    const LIGHT_DISCRIMINATOR_SLICE: &'static [u8] = b"queueacc";
}

impl<const BATCH: usize, const ZKP: usize> std::fmt::Debug for BatchedQueueAccount<'_, BATCH, ZKP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchedQueueAccount")
            .field("pubkey", &self.pubkey)
            .field("metadata", &self.layout.metadata)
            .finish()
    }
}

impl<const BATCH: usize, const ZKP: usize> PartialEq for BatchedQueueAccount<'_, BATCH, ZKP> {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
            && self.layout.discriminator == other.layout.discriminator
            && self.layout.metadata == other.layout.metadata
            && self.layout.value_vecs == other.layout.value_vecs
            && self.layout.hash_chains == other.layout.hash_chains
    }
}

impl<'a, const BATCH: usize, const ZKP: usize> BatchedQueueAccount<'a, BATCH, ZKP> {
    /// Deserialize an output BatchedQueueAccount from account info.
    /// Should be used in solana programs.
    /// Checks that:
    /// 1. the account owner is `program_id`,
    /// 2. discriminator,
    /// 3. queue type is output queue type.
    pub fn output_from_account_info(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedQueueAccount<'a, BATCH, ZKP>, BatchedMerkleTreeError> {
        Self::from_account_info::<OUTPUT_STATE_QUEUE_TYPE_V2>(program_id, account_info)
    }

    /// Deserialize a BatchedQueueAccount from account info.
    /// Should be used in solana programs.
    /// Checks the program owner, discriminator and queue type.
    fn from_account_info<const QUEUE_TYPE: u64>(
        program_id: &[u8; 32],
        account_info: &mut AccountView,
    ) -> Result<BatchedQueueAccount<'a, BATCH, ZKP>, BatchedMerkleTreeError> {
        check_account_info::<Self>(program_id, account_info)?;
        let queue_pubkey = *account_info.address();
        let account_data = &mut account_info.try_borrow_mut()?;
        // Necessary to convince the borrow checker.
        let account_data: &'a mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(account_data.as_mut_ptr(), account_data.len())
        };
        Self::from_bytes::<QUEUE_TYPE>(account_data, queue_pubkey)
    }

    /// Deserialize a BatchedQueueAccount from bytes.
    /// Should only be used in client.
    /// Checks the discriminator and queue type.
    #[cfg(not(target_os = "solana"))]
    pub fn output_from_bytes(
        account_data: &'a mut [u8],
    ) -> Result<BatchedQueueAccount<'a, BATCH, ZKP>, BatchedMerkleTreeError> {
        light_account_checks::checks::check_discriminator::<Self>(account_data)?;
        Self::from_bytes::<OUTPUT_STATE_QUEUE_TYPE_V2>(account_data, Pubkey::default())
    }

    fn from_bytes<const QUEUE_TYPE: u64>(
        account_data: &'a mut [u8],
        pubkey: Pubkey,
    ) -> Result<BatchedQueueAccount<'a, BATCH, ZKP>, BatchedMerkleTreeError> {
        let layout: &'a mut QueueAccountLayout<BATCH, ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;

        if layout.metadata.metadata.queue_type != QUEUE_TYPE {
            return Err(MerkleTreeMetadataError::InvalidQueueType.into());
        }

        Ok(BatchedQueueAccount { pubkey, layout })
    }

    pub fn init(
        account_data: &'a mut [u8],
        metadata: QueueMetadata,
        output_queue_batch_size: u64,
        output_queue_zkp_batch_size: u64,
        pubkey: Pubkey,
        tree_capacity: u64,
    ) -> Result<BatchedQueueAccount<'a, BATCH, ZKP>, BatchedMerkleTreeError> {
        if account_data.len() != size_of::<QueueAccountLayout<BATCH, ZKP>>() {
            return Err(ZeroCopyError::Size.into());
        }

        let layout: &'a mut QueueAccountLayout<BATCH, ZKP> =
            wincode::deserialize_mut(account_data).map_err(|_| ZeroCopyError::Size)?;
        layout.discriminator = Self::LIGHT_DISCRIMINATOR;

        layout.metadata.init(
            metadata,
            output_queue_batch_size,
            output_queue_zkp_batch_size,
            &pubkey,
            tree_capacity,
        )?;

        if layout
            .metadata
            .batch_metadata
            .queue_account_size(layout.metadata.metadata.queue_type)?
            != size_of::<QueueAccountLayout<BATCH, ZKP>>()
        {
            return Err(ZeroCopyError::Size.into());
        }

        Ok(BatchedQueueAccount { pubkey, layout })
    }

    /// Insert a value into the current batch
    /// of this output queue account.
    /// 1. insert value into a value vec and hash chain store.
    /// 2. Increment next_index.
    pub fn insert_into_current_batch(
        &mut self,
        hash_chain_value: &[u8; 32],
        current_slot: &u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        let current_index = self.batch_metadata.next_index;

        {
            let QueueAccountLayout {
                metadata,
                value_vecs,
                hash_chains,
                ..
            } = &mut *self.layout;
            let queue_type = metadata.metadata.queue_type;
            let [vv0, vv1] = value_vecs;
            let mut value_stores = [&mut vv0[..], &mut vv1[..]];
            let [hc0, hc1] = hash_chains;
            let mut hash_chain_stores = [&mut hc0[..], &mut hc1[..]];
            insert_into_current_queue_batch::<0, 0>(
                queue_type,
                &mut metadata.batch_metadata,
                &mut value_stores,
                None,
                &mut hash_chain_stores,
                hash_chain_value,
                None,
                Some(current_index),
                current_slot,
            )?;
        }
        self.layout.metadata.batch_metadata.next_index += 1;

        Ok(())
    }

    /// Proves inclusion of leaf index if it exists in one of the batches.
    /// 1. Iterate over all batches
    /// 2. Check if leaf index could exist in the batch.
    ///    2.1 If yes, check whether value at index is equal to hash_chain_value.
    ///    Throw error if not.
    /// 3. Return true if leaf index exists in one of the batches.
    ///
    /// Note, this method does not fail but returns `false`
    ///     if the leaf index is out of range for any batch.
    pub fn prove_inclusion_by_index(
        &mut self,
        leaf_index: u64,
        hash_chain_value: &[u8; 32],
    ) -> Result<bool, BatchedMerkleTreeError> {
        self.internal_prove_inclusion_by_index::<false>(leaf_index, hash_chain_value)
    }

    fn internal_prove_inclusion_by_index<const ZERO_OUT: bool>(
        &mut self,
        leaf_index: u64,
        hash_chain_value: &[u8; 32],
    ) -> Result<bool, BatchedMerkleTreeError> {
        if leaf_index >= self.batch_metadata.next_index {
            return Err(BatchedMerkleTreeError::InvalidIndex);
        }
        let QueueAccountLayout {
            metadata,
            value_vecs,
            ..
        } = &mut *self.layout;
        for (batch_index, batch) in metadata.batch_metadata.batches.iter().enumerate() {
            if batch.leaf_index_exists(leaf_index) {
                let index = batch.get_value_index_in_batch(leaf_index)?;
                let element = value_vecs
                    .get_mut(batch_index)
                    .and_then(|vec| vec.get_mut(index as usize))
                    .ok_or(BatchedMerkleTreeError::InclusionProofByIndexFailed)?;

                if *element == *hash_chain_value {
                    if ZERO_OUT {
                        *element = [0u8; 32];
                    }
                    return Ok(true);
                } else {
                    #[cfg(feature = "log")]
                    {
                        solana_msg::msg!(
                            "Index found but value doesn't match leaf_index {} compressed account hash: {:?} expected compressed account hash {:?}. (If the expected element is [0u8;32] it was already spent. Other possibly causes, data hash, discriminator, leaf index, or Merkle tree mismatch.)",
                            leaf_index,
                            hash_chain_value,*element
                        );
                    }
                    return Err(BatchedMerkleTreeError::InclusionProofByIndexFailed);
                }
            }
        }
        Ok(false)
    }

    /// Zero out a leaf by index if it exists in the queues hash_chain_value vec.
    /// If prove_by_index is true fail if leaf is not found.
    pub fn prove_inclusion_by_index_and_zero_out_leaf(
        &mut self,
        leaf_index: u64,
        hash_chain_value: &[u8; 32],
        prove_by_index: bool,
    ) -> Result<(), BatchedMerkleTreeError> {
        // Always check and zero out an existing value.
        let is_proven_by_index =
            self.internal_prove_inclusion_by_index::<true>(leaf_index, hash_chain_value)?;
        if is_proven_by_index {
            return Ok(());
        }
        // If no value is found and a check is not enforced return ok.
        if prove_by_index {
            #[cfg(feature = "log")]
            {
                solana_msg::msg!(
                   "leaf_index {} compressed account hash: {:?}. Possibly causes, leaf index, or Merkle tree mismatch.)",
                    leaf_index,
                    hash_chain_value
                );
            }
            Err(BatchedMerkleTreeError::InclusionProofByIndexFailed)
        } else {
            Ok(())
        }
    }

    pub fn get_metadata(&self) -> &BatchedQueueMetadata {
        &self.layout.metadata
    }

    pub fn get_metadata_mut(&mut self) -> &mut BatchedQueueMetadata {
        &mut self.layout.metadata
    }

    /// Returns the number of elements inserted in the current batch.
    /// If current batch state is inserted, returns 0.
    pub fn get_num_inserted_in_current_batch(&self) -> u64 {
        let current_batch = self.batch_metadata.currently_processing_batch_index as usize;
        if self.batch_metadata.batches[current_batch].get_state() == BatchState::Inserted {
            0
        } else {
            self.batch_metadata.batches[current_batch].get_num_inserted_elements()
        }
    }

    /// Returns true if the pubkey is the associated Merkle tree of the queue.
    pub fn is_associated(&self, pubkey: &Pubkey) -> bool {
        self.layout.metadata.metadata.associated_merkle_tree == *pubkey
    }

    /// Check if the pubkey is the associated Merkle tree of the queue.
    pub fn check_is_associated(&self, pubkey: &Pubkey) -> Result<(), BatchedMerkleTreeError> {
        if !self.is_associated(pubkey) {
            return Err(MerkleTreeMetadataError::MerkleTreeAndQueueNotAssociated.into());
        }
        Ok(())
    }

    /// Returns true if the tree is full.
    pub fn tree_is_full(&self) -> bool {
        self.batch_metadata.next_index >= self.tree_capacity
    }

    /// Check if the tree is full.
    pub fn check_tree_is_full(&self) -> Result<(), BatchedMerkleTreeError> {
        if self.tree_is_full() {
            return Err(BatchedMerkleTreeError::TreeIsFull);
        }
        Ok(())
    }

    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }
}

impl<const BATCH: usize, const ZKP: usize> Deref for BatchedQueueAccount<'_, BATCH, ZKP> {
    type Target = BatchedQueueMetadata;

    fn deref(&self) -> &Self::Target {
        &self.layout.metadata
    }
}

impl<const BATCH: usize, const ZKP: usize> DerefMut for BatchedQueueAccount<'_, BATCH, ZKP> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.layout.metadata
    }
}

/// Insert a value into the current batch.
/// - Input & address queues: Insert into bloom filter & hash chain.
/// - Output queue: Insert into value vec & hash chain.
///
/// Steps:
/// 1. Check if the current batch is ready.
///    1.1. If the current batch is inserted, clear the batch.
/// 2. Insert value into the current batch.
/// 3. If batch is full, increment currently_processing_batch_index.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub(crate) fn insert_into_current_queue_batch<const NUM_ITERS: usize, const BYTES: usize>(
    queue_type: u64,
    batch_metadata: &mut QueueBatches,
    value_vecs: &mut [&mut [[u8; 32]]],
    bloom_filters: Option<&mut [BloomFilter<NUM_ITERS, BYTES>; 2]>,
    hash_chain_stores: &mut [&mut [[u8; 32]]],
    hash_chain_value: &[u8; 32],
    bloom_filter_value: Option<&[u8; 32]>,
    current_index: Option<u64>,
    current_slot: &u64,
) -> Result<(), BatchedMerkleTreeError> {
    let batch_index = batch_metadata.currently_processing_batch_index as usize;
    let value_store: Option<&mut [[u8; 32]]> =
        value_vecs.get_mut(batch_index).map(|vec| &mut **vec);
    let hash_chain_store: Option<&mut [[u8; 32]]> =
        hash_chain_stores.get_mut(batch_index).map(|vec| &mut **vec);
    let current_batch = batch_metadata.get_current_batch_mut();
    // 1. Check that the current batch is ready (BatchState::Fill).
    //      1.1. If the current batch is inserted, clear the batch.
    {
        let clear_batch = current_batch.get_state() == BatchState::Inserted;
        if current_batch.get_state() == BatchState::Fill {
            // Do nothing, checking most common case first.
        } else if clear_batch {
            // Clear the batch if it is inserted.

            // If a batch contains a bloom filter it must be zeroed by a forester.
            if queue_type != QueueType::OutputStateV2 as u64
                && !current_batch.bloom_filter_is_zeroed()
            {
                return Err(BatchedMerkleTreeError::BloomFilterNotZeroed);
            }
            // Advance the state to fill and reset the number of inserted elements.
            // If Some(current_index) set it as start index.
            // Reset, sequence number, root index, bloom filter zeroed, num_inserted_zkps
            // start_slot, start_slot_is_set.
            current_batch.advance_state_to_fill(current_index)?;
        } else {
            // We expect to insert into the current batch.
            #[cfg(feature = "log")]
            for batch in batch_metadata.batches.iter() {
                solana_msg::msg!("batch {:?}", batch);
            }
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
    }

    // 2. Insert value into the current batch.
    let queue_type = QueueType::from(queue_type);
    match queue_type {
        QueueType::InputStateV2 | QueueType::AddressV2 => current_batch.insert(
            bloom_filter_value.unwrap(),
            hash_chain_value,
            bloom_filters.ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?,
            hash_chain_store.unwrap(),
            batch_index,
            current_slot,
        ),
        QueueType::OutputStateV2 => current_batch.store_and_hash_value(
            hash_chain_value,
            value_store.unwrap(),
            hash_chain_store.unwrap(),
            current_slot,
        ),
    }?;

    // 3. If batch is full, increment currently_processing_batch_index.
    batch_metadata.increment_currently_processing_batch_index_if_full();

    Ok(())
}

pub fn get_output_queue_account_size(batch_size: u64, zkp_batch_size: u64) -> usize {
    let metadata = BatchedQueueMetadata {
        metadata: QueueMetadata::default(),
        batch_metadata: QueueBatches {
            num_batches: NUM_BATCHES as u64,
            batch_size,
            zkp_batch_size,
            ..Default::default()
        },
        ..Default::default()
    };
    metadata
        .batch_metadata
        .queue_account_size(QueueType::OutputStateV2 as u64)
        .unwrap()
}

#[cfg(feature = "test-only")]
pub mod test_utils {
    use super::*;
    use crate::{
        constants::{NUM_BATCHES, TEST_DEFAULT_BATCH_SIZE, TEST_DEFAULT_ZKP_BATCH_SIZE},
        initialize_state_tree::InitStateTreeAccountsInstructionData,
    };
    pub fn get_output_queue_account_size_default() -> usize {
        let batch_metadata = BatchedQueueMetadata {
            metadata: QueueMetadata::default(),
            batch_metadata: QueueBatches {
                num_batches: NUM_BATCHES as u64,
                batch_size: TEST_DEFAULT_BATCH_SIZE,
                zkp_batch_size: TEST_DEFAULT_ZKP_BATCH_SIZE,
                ..Default::default()
            },
            ..Default::default()
        };
        batch_metadata
            .batch_metadata
            .queue_account_size(QueueType::OutputStateV2 as u64)
            .unwrap()
    }

    pub fn get_output_queue_account_size_from_params(
        ix_data: InitStateTreeAccountsInstructionData,
    ) -> usize {
        let metadata = BatchedQueueMetadata {
            metadata: QueueMetadata::default(),
            batch_metadata: QueueBatches {
                num_batches: NUM_BATCHES as u64,
                batch_size: ix_data.output_queue_batch_size,
                zkp_batch_size: ix_data.output_queue_zkp_batch_size,
                ..Default::default()
            },
            ..Default::default()
        };
        metadata
            .batch_metadata
            .queue_account_size(QueueType::OutputStateV2 as u64)
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assert_queue_inited(
        batch_metadata: QueueBatches,
        ref_batch_metadata: QueueBatches,
        queue_type: u64,
        num_value_vecs: usize,
        value_vec_capacity: usize,
    ) {
        assert_eq!(
            batch_metadata, ref_batch_metadata,
            "batch_metadata mismatch"
        );

        if queue_type == QueueType::OutputStateV2 as u64 {
            assert_eq!(num_value_vecs, NUM_BATCHES, "value_vecs mismatch");
            assert_eq!(
                value_vec_capacity, batch_metadata.batch_size as usize,
                "batch_size mismatch"
            );
        } else {
            assert_eq!(num_value_vecs, 0, "value_vecs mismatch");
        }
        for batch in batch_metadata.batches.iter() {
            assert_eq!(batch.get_num_inserted_elements(), 0, "batch_size mismatch");
        }
    }
    pub fn assert_queue_zero_copy_inited<const BATCH: usize, const ZKP: usize>(
        account_data: &mut [u8],
        ref_account: BatchedQueueMetadata,
    ) {
        let account = BatchedQueueAccount::<BATCH, ZKP>::output_from_bytes(account_data)
            .expect("from_bytes_unchecked_mut failed");
        let batch_metadata = account.batch_metadata;
        let queue_type = account.layout.metadata.metadata.queue_type;
        assert_eq!(
            account.layout.metadata.metadata, ref_account.metadata,
            "metadata mismatch"
        );
        assert_queue_inited(
            batch_metadata,
            ref_account.batch_metadata,
            queue_type,
            NUM_BATCHES,
            BATCH,
        );
    }
}

#[cfg(feature = "test-only")]
#[test]
fn test_from_bytes_invalid_tree_type() {
    use crate::queue::test_utils::get_output_queue_account_size_default;
    let mut account_data = vec![0u8; get_output_queue_account_size_default()];
    let account =
        BatchedQueueAccount::<50, 5>::from_bytes::<6>(&mut account_data, Pubkey::default());
    assert_eq!(
        account.unwrap_err(),
        MerkleTreeMetadataError::InvalidQueueType.into()
    );
}

#[test]
fn test_batched_queue_metadata_init() {
    let mut metadata = BatchedQueueMetadata::default();
    let mt_pubkey = Pubkey::new_unique();
    let queue_metadata = QueueMetadata {
        associated_merkle_tree: mt_pubkey,
        ..Default::default()
    };
    let batch_size = 4;
    let zkp_batch_size = 2;
    let queue_pubkey = Pubkey::new_unique();

    let tree_capacity = 16; // 2^4 for test purposes
    let result = metadata.init(
        queue_metadata,
        batch_size,
        zkp_batch_size,
        &queue_pubkey,
        tree_capacity,
    );

    assert!(result.is_ok());
    assert_eq!(metadata.metadata, queue_metadata);
    for (i, batch) in metadata.batch_metadata.batches.iter().enumerate() {
        assert_eq!(batch.batch_size, batch_size);
        assert_eq!(batch.zkp_batch_size, zkp_batch_size);
        assert_eq!(batch.start_index, batch_size * (i as u64));
    }
    let hashed_merkle_tree_pubkey = hash_to_bn254_field_size_be(&mt_pubkey.to_bytes());
    let hashed_queue_pubkey = hash_to_bn254_field_size_be(&queue_pubkey.to_bytes());
    assert_eq!(
        metadata.hashed_merkle_tree_pubkey,
        hashed_merkle_tree_pubkey
    );
    assert_eq!(metadata.hashed_queue_pubkey, hashed_queue_pubkey);
    assert_eq!(metadata.tree_capacity, tree_capacity);
}

#[test]
fn test_check_is_associated() {
    let mut account_data = vec![0u8; get_output_queue_account_size(4, 2)];
    let mut queue_metadata = QueueMetadata::default();
    let associated_merkle_tree = Pubkey::new_unique();
    queue_metadata.associated_merkle_tree = associated_merkle_tree;
    queue_metadata.queue_type = QueueType::OutputStateV2 as u64;
    let batch_size = 4;
    let zkp_batch_size = 2;
    let account = BatchedQueueAccount::<4, 2>::init(
        &mut account_data,
        queue_metadata,
        batch_size,
        zkp_batch_size,
        Pubkey::new_unique(),
        16, // 2^4 for test purposes
    )
    .unwrap();
    // 1. Functional
    {
        account
            .check_is_associated(&associated_merkle_tree)
            .unwrap();
        assert!(account.is_associated(&associated_merkle_tree));
    }
    // 2. Failing
    {
        let other_merkle_tree = Pubkey::new_unique();
        assert_eq!(
            account.check_is_associated(&other_merkle_tree),
            Err(MerkleTreeMetadataError::MerkleTreeAndQueueNotAssociated.into())
        );
        assert!(!account.is_associated(&other_merkle_tree));
    }
}

#[test]
fn test_pubkey() {
    let mut account_data = vec![0u8; get_output_queue_account_size(4, 2)];
    let mut queue_metadata = QueueMetadata::default();
    let associated_merkle_tree = Pubkey::new_unique();
    queue_metadata.associated_merkle_tree = associated_merkle_tree;
    queue_metadata.queue_type = QueueType::OutputStateV2 as u64;
    let batch_size = 4;
    let zkp_batch_size = 2;
    let pubkey = Pubkey::new_unique();
    let account = BatchedQueueAccount::<4, 2>::init(
        &mut account_data,
        queue_metadata,
        batch_size,
        zkp_batch_size,
        pubkey,
        16, // 2^4 for test purposes
    )
    .unwrap();
    assert_eq!(*account.pubkey(), pubkey);
}

#[test]
fn test_tree_capacity_is_set_correctly() {
    let mut account_data = vec![0u8; get_output_queue_account_size(4, 2)];
    let mut queue_metadata = QueueMetadata::default();
    let associated_merkle_tree = Pubkey::new_unique();
    queue_metadata.associated_merkle_tree = associated_merkle_tree;
    queue_metadata.queue_type = QueueType::OutputStateV2 as u64;
    let batch_size = 4;
    let zkp_batch_size = 2;
    let pubkey = Pubkey::new_unique();
    let tree_capacity = 1024; // 2^10

    let account = BatchedQueueAccount::<4, 2>::init(
        &mut account_data,
        queue_metadata,
        batch_size,
        zkp_batch_size,
        pubkey,
        tree_capacity,
    )
    .unwrap();

    // Verify tree_capacity is correctly set
    assert_eq!(account.tree_capacity, tree_capacity);

    // Verify tree_is_full works correctly
    assert!(!account.tree_is_full()); // Should not be full initially
    assert!(account.check_tree_is_full().is_ok());
}
