use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
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
    /// Reserved for account-layout compatibility.
    pub sequence_number: u64,
    /// Start leaf index of the first
    pub start_index: u64,
    /// Reserved for account-layout compatibility.
    pub root_index: u32,
    _padding: [u8; 4],
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
            _padding: [0u8; 4],
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

    /// State read for account-data paths: an out-of-range raw state is an
    /// error, never a panic. `get_state` (which panics on corrupt data) is
    /// for tests that construct the batch in memory.
    pub(crate) fn checked_state(&self) -> Result<BatchState, BatchedMerkleTreeError> {
        self.try_get_state()
            .ok_or(BatchedMerkleTreeError::InvalidBatchState)
    }

    pub fn reclaimable_sequence(&self) -> Result<u64, BatchedMerkleTreeError> {
        self.start_index
            .checked_add(self.batch_size)
            .and_then(|end| end.checked_sub(1))
            .ok_or(BatchedMerkleTreeError::ArithmeticOverflow)
    }

    pub fn is_reclaimable(&self, close_before_index: u64) -> bool {
        self.reclaimable_sequence()
            .is_ok_and(|sequence| close_before_index >= sequence)
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    /// `start_index` is the first queue index covered by the reused batch.
    pub fn advance_state_to_fill(
        &mut self,
        start_index: u64,
    ) -> Result<(), BatchedMerkleTreeError> {
        if self.checked_state()? != BatchState::Inserted {
            #[cfg(feature = "log")]
            solana_msg::msg!(
                "Batch is in incorrect state {} expected BatchState::Inserted 1",
                self.state
            );
            return Err(BatchedMerkleTreeError::BatchNotReady);
        }
        // A reused batch is a fresh batch over a later queue range, so rebuild it
        // instead of resetting counters one by one: every field is then reset by
        // construction, including the reserved words.
        *self = Batch::new(self.batch_size, self.zkp_batch_size, start_index);
        Ok(())
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    pub fn advance_state_to_inserted(&mut self) -> Result<(), BatchedMerkleTreeError> {
        if self.checked_state()? == BatchState::Full {
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
        if self.checked_state()? == BatchState::Fill {
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
        if self.checked_state()? == BatchState::Inserted {
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

    /// Returns the number of zkp batches in the batch.
    pub fn get_num_zkp_batches(&self) -> u64 {
        self.batch_size / self.zkp_batch_size
    }

    /// Add a value to the current hash chain, and advance batch state.
    /// Never mutates on error: all of its failure points (batch state, store
    /// capacity, hashing) precede the write.
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
        if self.checked_state()? != BatchState::Fill {
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

    /// Marks the batch as inserted in the merkle tree.
    /// 1. Checks that the batch is ready.
    /// 2. increments the number of inserted zkps.
    /// 3. If all zkps are inserted, sets the state to inserted.
    /// 4. Returns the updated state of the batch.
    pub fn mark_as_inserted_in_merkle_tree(
        &mut self,
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
        }

        self.checked_state()
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
        for i in 0..batch.get_num_zkp_batches() {
            batch.mark_as_inserted_in_merkle_tree().unwrap();
            if i != batch.get_num_zkp_batches() - 1 {
                assert_eq!(batch.get_state(), BatchState::Full);
                assert_eq!(batch.num_inserted, 0);
                assert_eq!(batch.get_current_zkp_batch_index(), 5);
                assert_eq!(batch.get_num_inserted_zkps(), i + 1);
            } else {
                assert_eq!(batch.get_state(), BatchState::Inserted);
                assert_eq!(batch.num_inserted, 0);
                assert_eq!(batch.get_current_zkp_batch_index(), 5);
                assert_eq!(batch.get_num_inserted_zkps(), i + 1);
            }
        }
        assert_eq!(batch.get_state(), BatchState::Inserted);
        assert_eq!(batch.num_inserted, 0);
        let mut ref_batch = get_test_batch();
        ref_batch.state = BatchState::Inserted.into();
        ref_batch.num_inserted_zkp_batches = 5;
        ref_batch.num_full_zkp_batches = 5;
        assert_eq!(batch, ref_batch);
        batch.advance_state_to_fill(1).unwrap();
        let mut ref_batch = get_test_batch();
        ref_batch.start_index = 1;
        assert_eq!(batch, ref_batch);
    }

    #[test]
    fn test_insert() {
        let mut batch = get_test_batch();
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_zkp_batches() as usize];

        let mut ref_batch = get_test_batch();
        for i in 0..batch.batch_size {
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
            let result = batch.add_to_hash_chain(&value, &mut hash_chain_store);
            assert!(result.is_ok(), "Failed result: {:?}", result);
            assert_eq!(hash_chain_store[chain_index], ref_hash_chain);

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
        test_mark_as_inserted(batch);
    }

    #[test]
    fn test_add_to_hash_chain() {
        let mut batch = get_test_batch();
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_zkp_batches() as usize];
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

    /// A failed insert must not mutate the batch or the hash chain store: host
    /// callers keep the state after an error.
    #[test]
    fn test_add_to_hash_chain_is_error_atomic() {
        let mut batch = Batch::new(500, 100, 0);
        batch.advance_state_to_full().unwrap();
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_zkp_batches() as usize];
        let batch_before = batch;
        let chain_before = hash_chain_store.clone();
        assert_eq!(
            batch
                .add_to_hash_chain(&[9u8; 32], &mut hash_chain_store)
                .unwrap_err(),
            BatchedMerkleTreeError::BatchNotReady
        );
        assert_eq!(batch, batch_before);
        assert_eq!(hash_chain_store, chain_before);
    }

    #[test]
    fn test_getters() {
        let mut batch = get_test_batch();
        assert_eq!(batch.get_num_zkp_batches(), 5);
        assert_eq!(batch.get_state(), BatchState::Fill);
        assert_eq!(batch.num_inserted, 0);
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
        let mut hash_chain_store = vec![[0u8; 32]; batch.get_num_zkp_batches() as usize];

        for i in 0..batch.batch_size + 10 {
            let mut value = [0u8; 32];
            value[24..].copy_from_slice(&i.to_be_bytes());
            if i < batch.batch_size {
                batch
                    .add_to_hash_chain(&value, &mut hash_chain_store)
                    .unwrap();
            }
            #[allow(clippy::manual_is_multiple_of)]
            if (i + 1) % batch.zkp_batch_size == 0 && i != 0 {
                assert_eq!(
                    batch.get_first_ready_zkp_batch().unwrap(),
                    i / batch.zkp_batch_size
                );
                batch.mark_as_inserted_in_merkle_tree().unwrap();
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
            let result = batch.advance_state_to_fill(0);
            assert_eq!(result, Err(BatchedMerkleTreeError::BatchNotReady));
        }
        batch.advance_state_to_full().unwrap();
        assert_eq!(batch.get_state(), BatchState::Full);
        {
            let result = batch.advance_state_to_full();
            assert_eq!(result, Err(BatchedMerkleTreeError::BatchNotReady));
            let result = batch.advance_state_to_fill(0);
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
        batch.advance_state_to_fill(123).unwrap();
        assert_eq!(batch.start_index, 123);
        assert_eq!(batch.num_inserted, 0);
        assert_eq!(batch.get_num_inserted_elements(), 0);
    }

    /// Account-data paths must return `InvalidBatchState` for a corrupt state
    /// word instead of panicking in `From<u64>`.
    #[test]
    fn corrupt_state_errors_instead_of_panicking() {
        let mut batch = get_test_batch();
        batch.state = 3;
        assert_eq!(
            batch.advance_state_to_full().unwrap_err(),
            BatchedMerkleTreeError::InvalidBatchState
        );
        assert_eq!(
            batch.advance_state_to_inserted().unwrap_err(),
            BatchedMerkleTreeError::InvalidBatchState
        );
        assert_eq!(
            batch.advance_state_to_fill(0).unwrap_err(),
            BatchedMerkleTreeError::InvalidBatchState
        );
        assert_eq!(
            batch.get_first_ready_zkp_batch().unwrap_err(),
            BatchedMerkleTreeError::InvalidBatchState
        );
        assert_eq!(
            batch
                .add_to_hash_chain(&[1u8; 32], &mut [[0u8; 32]; 5])
                .unwrap_err(),
            BatchedMerkleTreeError::InvalidBatchState
        );
        assert_eq!(
            batch.mark_as_inserted_in_merkle_tree().unwrap_err(),
            BatchedMerkleTreeError::InvalidBatchState
        );
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
