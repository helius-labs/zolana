use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zolana_bloom_filter::BloomFilter;
use zolana_hasher::{Hasher, Poseidon};

use crate::{errors::BatchedMerkleTreeError, BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[repr(u64)]
pub enum BatchState {
    /// Batch can be filled with values.
    Fill,
    /// Batch has been inserted into the tree.
    Inserted,
    /// Batch is full.
    Full,
}

impl From<u64> for BatchState {
    fn from(value: u64) -> Self {
        match value {
            0 => BatchState::Fill,
            1 => BatchState::Inserted,
            2 => BatchState::Full,
            _ => panic!("Invalid BatchState value"),
        }
    }
}

impl From<BatchState> for u64 {
    fn from(val: BatchState) -> Self {
        val as u64
    }
}

/// Batch structure that holds
/// the metadata and state of a batch.
///
/// A batch:
/// - has a size and a number of zkp batches.
/// - size must be divisible by zkp batch size.
/// - is part of a queue, each queue has two batches.
/// - is inserted into the tree by zkp batch.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    KnownLayout,
    Immutable,
    IntoBytes,
    FromBytes,
    Default,
    BorshSerialize,
    BorshDeserialize,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
pub struct Batch {
    /// Number of inserted elements in the zkp batch.
    num_inserted: u64,
    state: u64,
    /// Number of full zkp batches in the batch,
    /// that are ready to be inserted into the tree.
    pub(crate) num_full_zkp_batches: u64,
    /// Number zkp batches that are inserted into the tree.
    num_inserted_zkp_batches: u64,
    /// Number of elements in a batch.
    pub batch_size: u64,
    /// Number of elements in a zkp batch.
    /// A batch consists out of one or more zkp batches.
    pub zkp_batch_size: u64,
    /// Sequence number when it is save to clear the batch without advancing to
    /// the saved root index.
    pub sequence_number: u64,
    /// Start leaf index of the first
    pub start_index: u64,
    pub root_index: u32,
    bloom_filter_is_zeroed: u8,
    _padding: [u8; 3],
}

impl Batch {
    pub fn new(batch_size: u64, zkp_batch_size: u64, start_index: u64) -> Self {
        Batch {
            batch_size,
            num_inserted: 0,
            state: BatchState::Fill.into(),
            zkp_batch_size,
            num_full_zkp_batches: 0,
            num_inserted_zkp_batches: 0,
            sequence_number: 0,
            root_index: 0,
            start_index,
            bloom_filter_is_zeroed: 0,
            _padding: [0u8; 3],
        }
    }

    /// Returns the state of the batch.
    pub fn get_state(&self) -> BatchState {
        self.state.into()
    }

    /// Non-panicking counterpart to [`get_state`](Self::get_state): returns
    /// `None` for an out-of-range raw state (e.g. a corrupt account whose layout
    /// still parses) instead of panicking in `From<u64>`.
    pub fn try_get_state(&self) -> Option<BatchState> {
        match self.state {
            0 => Some(BatchState::Fill),
            1 => Some(BatchState::Inserted),
            2 => Some(BatchState::Full),
            _ => None,
        }
    }

    pub fn bloom_filter_is_zeroed(&self) -> bool {
        self.bloom_filter_is_zeroed == 1
    }

    pub fn set_bloom_filter_to_zeroed(&mut self) {
        // 1 if bloom filter is zeroed
        // 0 if bloom filter is not zeroed
        self.bloom_filter_is_zeroed = 1;
    }

    pub fn set_bloom_filter_to_not_zeroed(&mut self) {
        // 1 if bloom filter is zeroed
        // 0 if bloom filter is not zeroed
        self.bloom_filter_is_zeroed = 0;
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    pub fn advance_state_to_fill(
        &mut self,
        start_index: Option<u64>,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.get_state() == BatchState::Inserted {
            self.state = BatchState::Fill.into();
            self.set_bloom_filter_to_not_zeroed();
            self.sequence_number = 0;
            self.root_index = 0;
            self.num_inserted_zkp_batches = 0;
            // Defensive: already 0 because Full is only reachable via
            // add_to_hash_chain, which zeroes num_inserted when the final zkp
            // batch completes; reset here so the invariant is local.
            self.num_inserted = 0;
            if let Some(start_index) = start_index {
                self.start_index = start_index;
            }
            self.num_full_zkp_batches = 0;
        } else {
            #[cfg(feature = "log")]
            solana_msg::msg!(
                "Batch is in incorrect state {} expected BatchState::Inserted 1",
                self.state
            );
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
        Ok(())
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    pub fn advance_state_to_inserted(&mut self) -> Result<(), BatchedMerkleTreeError> {
        if self.get_state() == BatchState::Full {
            self.state = BatchState::Inserted.into();
        } else {
            #[cfg(feature = "log")]
            solana_msg::msg!(
                "Batch is in incorrect state {} expected BatchState::Full 2",
                self.state
            );
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
        Ok(())
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    pub fn advance_state_to_full(&mut self) -> Result<(), BatchedMerkleTreeError> {
        if self.get_state() == BatchState::Fill {
            self.state = BatchState::Full.into();
        } else {
            #[cfg(feature = "log")]
            solana_msg::msg!(
                "Batch is in incorrect state {} expected BatchState::Fill 0",
                self.state
            );
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
        Ok(())
    }

    pub fn get_first_ready_zkp_batch(&self) -> Result<u64, BatchedMerkleTreeError> {
        if self.get_state() == BatchState::Inserted {
            Err(BatchedMerkleTreeError::BatchAlreadyInserted)
        } else if self.batch_is_ready_to_insert() {
            Ok(self.num_inserted_zkp_batches)
        } else {
            Err(BatchedMerkleTreeError::BatchNotReady)
        }
    }

    pub fn batch_is_ready_to_insert(&self) -> bool {
        self.num_full_zkp_batches > self.num_inserted_zkp_batches
    }

    /// Returns the number of zkp batch updates
    /// that are ready to be inserted into the tree.
    pub fn get_num_ready_zkp_updates(&self) -> u64 {
        self.num_full_zkp_batches
            .saturating_sub(self.num_inserted_zkp_batches)
    }

    /// Returns the number of inserted elements
    /// in the current zkp batch.
    pub fn get_num_inserted_zkp_batch(&self) -> u64 {
        self.num_inserted
    }

    /// Returns the current zkp batch index.
    /// New values are inserted into the current zkp batch.
    pub fn get_current_zkp_batch_index(&self) -> u64 {
        self.num_full_zkp_batches
    }

    /// Returns the number of inserted zkps.
    pub fn get_num_inserted_zkps(&self) -> u64 {
        self.num_inserted_zkp_batches
    }

    /// Returns the number of inserted elements in the batch.
    pub fn get_num_inserted_elements(&self) -> u64 {
        self.num_full_zkp_batches * self.zkp_batch_size + self.num_inserted
    }

    pub fn get_hash_chain_store_len(&self) -> u64 {
        self.num_full_zkp_batches + u64::from(self.num_inserted > 0)
    }

    /// Returns the number of zkp batches in the batch.
    pub fn get_num_zkp_batches(&self) -> u64 {
        self.batch_size / self.zkp_batch_size
    }

    /// Returns the number of the hash_chain stores.
    pub fn get_num_hash_chain_store(&self) -> usize {
        self.get_num_zkp_batches() as usize
    }

    /// Insert into the bloom filter and
    /// add value to current hash chain.
    /// (used by nullifier & address queues)
    /// 1. Add value to hash chain.
    /// 2. Insert value into the bloom filter at bloom_filter_index.
    /// 3. Check that value is not in any other bloom filter.
    pub fn insert<const NUM_ITERS: usize, const BYTES: usize>(
        &mut self,
        bloom_filter_value: &[u8; 32],
        hash_chain_value: &[u8; 32],
        bloom_filters: &mut [BloomFilter<NUM_ITERS, BYTES>; 2],
        hash_chain_store: &mut [[u8; 32]],
        bloom_filter_index: usize,
    ) -> Result<(), BatchedMerkleTreeError> {
        // 1. add value to hash chain
        self.add_to_hash_chain(hash_chain_value, hash_chain_store)?;
        // insert into bloom filter & check non inclusion
        {
            let other_bloom_filter_index = if bloom_filter_index == 0 { 1 } else { 0 };

            // 2. Insert value into the bloom filter at bloom_filter_index.
            bloom_filters
                .get_mut(bloom_filter_index)
                .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?
                .insert(bloom_filter_value)?;
            // 3. Check that value is not in any other bloom filter.
            Self::check_non_inclusion(
                bloom_filter_value,
                bloom_filters
                    .get(other_bloom_filter_index)
                    .ok_or(BatchedMerkleTreeError::InvalidBatchIndex)?,
            )?;
        }
        Ok(())
    }

    /// Add a value to the current hash chain, and advance batch state.
    /// 1. Check that the batch is ready.
    /// 2. If the zkp batch is empty, start a new hash chain.
    /// 3. If the zkp batch is not empty, add value to last hash chain.
    /// 4. If the zkp batch is full, increment the zkp batch index.
    /// 5. If all zkp batches are full, set batch state to full.
    pub fn add_to_hash_chain(
        &mut self,
        value: &[u8; 32],
        hash_chain_store: &mut [[u8; 32]],
    ) -> Result<(), BatchedMerkleTreeError> {
        // 1. Check that the batch is ready.
        if self.get_state() != BatchState::Fill {
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
        let hash_chain_index = self.num_full_zkp_batches as usize;
        let start_new_hash_chain = self.num_inserted == 0;
        if start_new_hash_chain {
            // 2. Start a new hash chain.
            let slot = hash_chain_store
                .get_mut(hash_chain_index)
                .ok_or(crate::zero_copy::ZeroCopyError::Full)?;
            *slot = *value;
        } else {
            // 3. Add value to last hash chain.
            let existing = *hash_chain_store
                .get(hash_chain_index)
                .ok_or(crate::zero_copy::ZeroCopyError::Full)?;
            let hash_chain = Poseidon::hashv(&[existing.as_slice(), value.as_slice()])?;
            let slot = hash_chain_store
                .get_mut(hash_chain_index)
                .ok_or(crate::zero_copy::ZeroCopyError::Full)?;
            *slot = hash_chain;
        }
        self.num_inserted += 1;

        // 4. If the zkp batch is full, increment the zkp batch index.
        let zkp_batch_is_full = self.num_inserted == self.zkp_batch_size;
        if zkp_batch_is_full {
            self.num_full_zkp_batches += 1;
            // To start a new hash chain in the next insertion
            // set num inserted to zero.
            self.num_inserted = 0;

            // 5. If all zkp batches are full, set batch state to full.
            let batch_is_full = self.num_full_zkp_batches == self.get_num_zkp_batches();
            if batch_is_full {
                self.advance_state_to_full()?;
            }
        }

        Ok(())
    }

    /// Checks that value is not in the bloom filter.
    pub fn check_non_inclusion<const NUM_ITERS: usize, const BYTES: usize>(
        value: &[u8; 32],
        bloom_filter: &BloomFilter<NUM_ITERS, BYTES>,
    ) -> Result<(), BatchedMerkleTreeError> {
        if bloom_filter.contains(value) {
            return Err(BatchedMerkleTreeError::NonInclusionCheckFailed);
        }
        Ok(())
    }

    /// Marks the batch as inserted in the merkle tree.
    /// 1. Checks that the batch is ready.
    /// 2. increments the number of inserted zkps.
    /// 3. If all zkps are inserted, sets the state to inserted.
    /// 4. Returns the updated state of the batch.
    pub fn mark_as_inserted_in_merkle_tree(
        &mut self,
        sequence_number: u64,
        root_index: u32,
        root_history_length: u32,
    ) -> Result<BatchState, BatchedMerkleTreeError> {
        // 1. Check that batch is ready.
        self.get_first_ready_zkp_batch()?;

        let num_zkp_batches = self.get_num_zkp_batches();

        // 2. increments the number of inserted zkps.
        self.num_inserted_zkp_batches += 1;
        // 3. If all zkp batches are inserted, sets the state to inserted.
        let batch_is_completely_inserted = self.num_inserted_zkp_batches == num_zkp_batches;
        if batch_is_completely_inserted {
            self.advance_state_to_inserted()?;
            // Saving sequence number and root index for the batch.
            // When the batch is cleared check that sequence number is greater or equal than self.sequence_number
            // if not advance current root index to root index
            self.sequence_number = sequence_number + root_history_length as u64;
            self.root_index = root_index;
        }

        Ok(self.get_state())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn get_test_batch() -> Batch {
        Batch::new(500, 100, 0)
    }

    /// simulate zkp batch insertion
    fn test_mark_as_inserted(mut batch: Batch) {
        let mut sequence_number = 10;
        let mut root_index = 20;
        let root_history_length = 23;
        for i in 0..batch.get_num_zkp_batches() {
            sequence_number += i;
            root_index += i as u32;
            batch
                .mark_as_inserted_in_merkle_tree(sequence_number, root_index, root_history_length)
                .unwrap();
            if i != batch.get_num_zkp_batches() - 1 {
                assert_eq!(batch.get_state(), BatchState::Full);
                assert_eq!(batch.get_num_inserted_zkp_batch(), 0);
                assert_eq!(batch.get_current_zkp_batch_index(), 5);
                assert_eq!(batch.get_num_inserted_zkps(), i + 1);
            } else {
                assert_eq!(batch.get_state(), BatchState::Inserted);
                assert_eq!(batch.get_num_inserted_zkp_batch(), 0);
                assert_eq!(batch.get_current_zkp_batch_index(), 5);
                assert_eq!(batch.get_num_inserted_zkps(), i + 1);
            }
        }
        assert_eq!(batch.get_state(), BatchState::Inserted);
        assert_eq!(batch.get_num_inserted_zkp_batch(), 0);
        let mut ref_batch = get_test_batch();
        ref_batch.state = BatchState::Inserted.into();
        ref_batch.root_index = root_index;
        ref_batch.sequence_number = sequence_number + root_history_length as u64;
        ref_batch.num_inserted_zkp_batches = 5;
        ref_batch.num_full_zkp_batches = 5;
        assert_eq!(batch, ref_batch);
        batch.advance_state_to_fill(Some(1)).unwrap();
        let mut ref_batch = get_test_batch();
        ref_batch.start_index = 1;
        assert_eq!(batch, ref_batch);
    }

    #[test]
    fn test_insert() {
        // Behavior Input queue
        let mut batch = get_test_batch();
        let mut blooms = [
            BloomFilter::<3, 20_000>::new(),
            BloomFilter::<3, 20_000>::new(),
        ];
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_hash_chain_store()];

        let mut ref_batch = get_test_batch();
        for processing_index in 0..=1 {
            for i in 0..(batch.batch_size / 2) {
                let i = i + (batch.batch_size / 2) * (processing_index as u64);
                ref_batch.num_inserted %= ref_batch.zkp_batch_size;

                let chain_index = batch.num_full_zkp_batches as usize;
                let mut value = [0u8; 32];
                value[24..].copy_from_slice(&i.to_be_bytes());
                #[allow(clippy::manual_is_multiple_of)]
                let ref_hash_chain = if i % batch.zkp_batch_size == 0 {
                    value
                } else {
                    Poseidon::hashv(&[&hash_chain_store[chain_index], &value]).unwrap()
                };
                let result = batch.insert(
                    &value,
                    &value,
                    &mut blooms,
                    &mut hash_chain_store,
                    processing_index,
                );
                // First insert should succeed
                assert!(result.is_ok(), "Failed result: {:?}", result);
                assert_eq!(hash_chain_store[chain_index], ref_hash_chain);

                {
                    let mut cloned_hash_chain_store = hash_chain_store.clone();
                    let mut batch = batch;
                    let mut cloned_blooms = blooms;
                    // Reinsert should fail
                    assert!(batch
                        .insert(
                            &value,
                            &value,
                            &mut cloned_blooms,
                            &mut cloned_hash_chain_store,
                            processing_index,
                        )
                        .is_err());
                }
                assert!(blooms.get(processing_index).unwrap().contains(&value));
                let other_index = if processing_index == 0 { 1 } else { 0 };
                Batch::check_non_inclusion(&value, blooms.get(other_index).unwrap()).unwrap();
                Batch::check_non_inclusion(&value, blooms.get(processing_index).unwrap())
                    .unwrap_err();

                ref_batch.num_inserted += 1;
                if ref_batch.num_inserted == ref_batch.zkp_batch_size {
                    ref_batch.num_full_zkp_batches += 1;
                    ref_batch.num_inserted = 0;
                }
                if i == batch.batch_size - 1 {
                    ref_batch.state = BatchState::Full.into();
                    ref_batch.num_inserted = 0;
                }
                assert_eq!(batch, ref_batch);
            }
        }
        test_mark_as_inserted(batch);
    }

    #[test]
    fn test_add_to_hash_chain() {
        let mut batch = get_test_batch();
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_hash_chain_store()];
        let value = [1u8; 32];

        assert!(batch
            .add_to_hash_chain(&value, &mut hash_chain_store)
            .is_ok());
        let mut ref_batch = get_test_batch();
        let user_hash_chain = value;
        ref_batch.num_inserted = 1;
        assert_eq!(batch, ref_batch);
        assert_eq!(hash_chain_store[0], user_hash_chain);
        let value = [2u8; 32];
        let ref_hash_chain = Poseidon::hashv(&[&user_hash_chain, &value]).unwrap();
        assert!(batch
            .add_to_hash_chain(&value, &mut hash_chain_store)
            .is_ok());

        ref_batch.num_inserted = 2;
        assert_eq!(batch, ref_batch);
        assert_eq!(hash_chain_store[0], ref_hash_chain);
    }

    #[test]
    fn test_check_non_inclusion() {
        for processing_index in 0..=1 {
            let mut batch = get_test_batch();

            let value = [1u8; 32];
            let mut blooms = [
                BloomFilter::<3, 20_000>::new(),
                BloomFilter::<3, 20_000>::new(),
            ];
            let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_hash_chain_store()];

            assert_eq!(
                Batch::check_non_inclusion(&value, blooms.get(processing_index).unwrap()),
                Ok(())
            );
            let ref_batch = get_test_batch();
            assert_eq!(batch, ref_batch);
            batch
                .insert(
                    &value,
                    &value,
                    &mut blooms,
                    &mut hash_chain_store,
                    processing_index,
                )
                .unwrap();
            assert!(
                Batch::check_non_inclusion(&value, blooms.get(processing_index).unwrap()).is_err()
            );

            let other_index = if processing_index == 0 { 1 } else { 0 };
            assert!(Batch::check_non_inclusion(&value, blooms.get(other_index).unwrap()).is_ok());
        }
    }

    #[test]
    fn test_getters() {
        let mut batch = get_test_batch();
        assert_eq!(batch.get_num_zkp_batches(), 5);
        assert_eq!(batch.get_num_hash_chain_store(), 5);
        assert_eq!(batch.get_state(), BatchState::Fill);
        assert_eq!(batch.get_num_inserted_zkp_batch(), 0);
        assert_eq!(batch.get_current_zkp_batch_index(), 0);
        assert_eq!(batch.get_num_inserted_zkps(), 0);
        batch.advance_state_to_full().unwrap();
        assert_eq!(batch.get_state(), BatchState::Full);
        batch.advance_state_to_inserted().unwrap();
        assert_eq!(batch.get_state(), BatchState::Inserted);
    }

    /// 1. Failing: empty batch
    /// 2. Functional: if zkp batch size is full else failing
    /// 3. Failing: batch is completely inserted
    #[test]
    fn test_can_insert_batch() {
        let mut batch = get_test_batch();
        assert_eq!(
            batch.get_first_ready_zkp_batch(),
            Err(BatchedMerkleTreeError::BatchNotReady)
        );
        let mut blooms = [
            BloomFilter::<3, 20_000>::new(),
            BloomFilter::<3, 20_000>::new(),
        ];
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_hash_chain_store()];

        for i in 0..batch.batch_size + 10 {
            let mut value = [0u8; 32];
            value[24..].copy_from_slice(&i.to_be_bytes());
            if i < batch.batch_size {
                batch
                    .insert(&value, &value, &mut blooms, &mut hash_chain_store, 0)
                    .unwrap();
            }
            #[allow(clippy::manual_is_multiple_of)]
            if (i + 1) % batch.zkp_batch_size == 0 && i != 0 {
                assert_eq!(
                    batch.get_first_ready_zkp_batch().unwrap(),
                    i / batch.zkp_batch_size
                );
                batch.mark_as_inserted_in_merkle_tree(0, 0, 0).unwrap();
            } else if i >= batch.batch_size {
                assert_eq!(
                    batch.get_first_ready_zkp_batch(),
                    Err(BatchedMerkleTreeError::BatchAlreadyInserted)
                );
            } else {
                assert_eq!(
                    batch.get_first_ready_zkp_batch(),
                    Err(BatchedMerkleTreeError::BatchNotReady)
                );
            }
        }
    }

    #[test]
    fn test_get_state() {
        let mut batch = get_test_batch();
        assert_eq!(batch.get_state(), BatchState::Fill);
        {
            let result = batch.advance_state_to_inserted();
            assert_eq!(result, Err(BatchedMerkleTreeError::BatchNotReady));
            let result = batch.advance_state_to_fill(None);
            assert_eq!(result, Err(BatchedMerkleTreeError::BatchNotReady));
        }
        batch.advance_state_to_full().unwrap();
        assert_eq!(batch.get_state(), BatchState::Full);
        {
            let result = batch.advance_state_to_full();
            assert_eq!(result, Err(BatchedMerkleTreeError::BatchNotReady));
            let result = batch.advance_state_to_fill(None);
            assert_eq!(result, Err(BatchedMerkleTreeError::BatchNotReady));
        }
        batch.advance_state_to_inserted().unwrap();
        assert_eq!(batch.get_state(), BatchState::Inserted);
    }

    #[test]
    fn advance_state_to_fill_resets_num_inserted() {
        let mut batch = get_test_batch();
        batch.num_inserted = 42;
        batch.state = BatchState::Inserted.into();
        batch.advance_state_to_fill(None).unwrap();
        assert_eq!(batch.num_inserted, 0);
        assert_eq!(batch.get_num_inserted_elements(), 0);
        assert_eq!(batch.get_hash_chain_store_len(), 0);
    }

    #[test]
    fn try_get_state_maps_known_states_and_returns_none_for_invalid() {
        let mut batch = get_test_batch();
        for (raw, state) in [
            (0, BatchState::Fill),
            (1, BatchState::Inserted),
            (2, BatchState::Full),
        ] {
            batch.state = raw;
            assert_eq!(batch.try_get_state(), Some(state));
        }

        batch.state = 3;
        assert_eq!(batch.try_get_state(), None);
    }

    #[test]
    fn test_bloom_filter_is_zeroed() {
        let mut batch = get_test_batch();
        assert!(!batch.bloom_filter_is_zeroed());
        batch.set_bloom_filter_to_zeroed();
        assert!(batch.bloom_filter_is_zeroed());
        batch.set_bloom_filter_to_not_zeroed();
        assert!(!batch.bloom_filter_is_zeroed());
    }

    #[test]
    fn test_num_ready_zkp_updates() {
        let mut batch = get_test_batch();
        assert_eq!(batch.get_num_ready_zkp_updates(), 0);
        batch.num_full_zkp_batches = 1;
        assert_eq!(batch.get_num_ready_zkp_updates(), 1);
        batch.num_inserted_zkp_batches = 1;
        assert_eq!(batch.get_num_ready_zkp_updates(), 0);
        batch.num_full_zkp_batches = 2;
        assert_eq!(batch.get_num_ready_zkp_updates(), 1);
    }

    #[test]
    fn test_get_num_inserted_elements() {
        let mut batch = get_test_batch();
        assert_eq!(batch.get_num_inserted_elements(), 0);
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_zkp_batches() as usize];

        for i in 0..batch.batch_size {
            let mut value = [0u8; 32];
            value[24..].copy_from_slice(&i.to_be_bytes());
            batch
                .add_to_hash_chain(&value, &mut hash_chain_store)
                .unwrap();
            assert_eq!(batch.get_num_inserted_elements(), i + 1);
        }
    }
}
