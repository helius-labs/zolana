use core::mem::{align_of, size_of};

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "test-only")]
use zerocopy::FromZeros;
use zerocopy::{FromBytes, Immutable, KnownLayout};
use zolana_hasher::{Hasher, Poseidon};

use crate::nullifier_tree::error::NullifierTreeError;

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

/// A verified but not yet applied ZKP batch update, stored in the ZKP batch it
/// belongs to. `occupied` marks a filled slot: a zeroed slot is empty.
#[repr(C)]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    KnownLayout,
    Immutable,
    FromBytes,
    BorshSerialize,
    BorshDeserialize,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
pub struct CachedTreeUpdate {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub occupied: u8,
}

impl CachedTreeUpdate {
    fn is_occupied(&self) -> bool {
        self.occupied != 0
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
    FromBytes,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Batch<const ZKP: usize> {
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
    pub sequence_number: u64, // TODO: remove
    /// Start leaf index of the first
    pub start_index: u64,
    /// Reserved for account-layout compatibility.
    pub root_index: u32, // TODO: remove
    _padding: [u8; 4],
    /// One Poseidon hash chain per ZKP batch. The chain at
    /// `num_full_zkp_batches` is the one insertions currently extend; the
    /// chains below it are complete and are the prover inputs of the pending
    /// tree updates.
    hash_chains: [[u8; 32]; ZKP],
    /// One cached tree update per ZKP batch, verified and waiting to be applied
    /// to the tree. The slot at `num_inserted_zkp_batches` is the next update
    /// that can be applied; a slot is cleared once its update is in the tree.
    cached_tree_updates: [CachedTreeUpdate; ZKP],
}

/// `repr(C)`: 72 metadata bytes, then one hash chain and one cached update per
/// ZKP batch. Both arrays are align-1, so the only implicit padding is the tail
/// that rounds the batch up to the alignment of its metadata words; the
/// production configuration (`ZKP = 120`) has none.
const fn batch_size_bytes(zkp: usize) -> usize {
    let unpadded = 72 + (32 + size_of::<CachedTreeUpdate>()) * zkp;
    unpadded.next_multiple_of(align_of::<Batch<1>>())
}

/// Two instantiations pin the size formula for every `ZKP`.
const _: () = {
    assert!(size_of::<CachedTreeUpdate>() == 65);
    assert!(size_of::<Batch<1>>() == batch_size_bytes(1));
    assert!(size_of::<Batch<9>>() == batch_size_bytes(9));
};

impl<const ZKP: usize> Batch<ZKP> {
    /// Initializes a batch in place on zeroed account data, a precondition the
    /// layout init relies on throughout (it never writes root-history slots
    /// past index 0 either).
    pub(crate) fn init(&mut self, batch_size: u64, zkp_batch_size: u64, start_index: u64) {
        self.reset(batch_size, zkp_batch_size, start_index);
    }

    /// Resets every metadata word, so a reused batch cannot inherit a counter
    /// or a reserved value from its previous queue range. The hash chains and
    /// cached updates need no zeroing: a filling batch writes a chain slot
    /// before anything reads it, and every cached update slot is cleared
    /// together with its consumed chain when its update lands in the tree, so
    /// a batch reaches `Inserted` with both arrays zeroed.
    fn reset(&mut self, batch_size: u64, zkp_batch_size: u64, start_index: u64) {
        self.num_inserted = 0;
        self.state = BatchState::Fill.into();
        self.num_full_zkp_batches = 0;
        self.num_inserted_zkp_batches = 0;
        self.batch_size = batch_size;
        self.zkp_batch_size = zkp_batch_size;
        self.sequence_number = 0;
        self.start_index = start_index;
        self.root_index = 0;
        self._padding = [0u8; 4];
    }

    /// Returns the complete or in-progress hash chain of a ZKP batch.
    pub fn hash_chain(&self, zkp_batch_index: usize) -> Option<[u8; 32]> {
        self.hash_chains.get(zkp_batch_index).copied()
    }

    /// Number of cached update slots, one per ZKP batch.
    pub fn cached_tree_update_capacity(&self) -> usize {
        self.cached_tree_updates.len()
    }

    /// Returns the cached update of a ZKP batch, or `None` for an
    /// out-of-range index or an empty slot.
    pub fn cached_tree_update(&self, zkp_batch_index: usize) -> Option<CachedTreeUpdate> {
        self.cached_tree_updates
            .get(zkp_batch_index)
            .copied()
            .filter(CachedTreeUpdate::is_occupied)
    }

    /// Stores a verified update in the slot of its ZKP batch.
    pub(crate) fn cache_tree_update(
        &mut self,
        zkp_batch_index: usize,
        update: CachedTreeUpdate,
    ) -> Result<(), NullifierTreeError> {
        *self
            .cached_tree_updates
            .get_mut(zkp_batch_index)
            .ok_or(NullifierTreeError::CachedTreeUpdateIndexOutOfRange)? = update;
        Ok(())
    }

    /// Clears an applied ZKP batch's slots: the cached update (`occupied = 0`)
    /// and the hash chain it was verified against, which is dead once the
    /// update is in the tree. A batch therefore reaches `Inserted` with both
    /// arrays fully zeroed.
    pub(crate) fn clear_cached_tree_update(
        &mut self,
        zkp_batch_index: usize,
    ) -> Result<(), NullifierTreeError> {
        self.evict_cached_tree_update(zkp_batch_index)?;
        *self
            .hash_chains
            .get_mut(zkp_batch_index)
            .ok_or(NullifierTreeError::CachedTreeUpdateIndexOutOfRange)? = [0u8; 32];
        Ok(())
    }

    /// Resets a ZKP batch's cached update to empty (`occupied = 0`), freeing
    /// the slot for a fresh proof. The hash chain must survive eviction: it is
    /// the only stored commitment to the queued leaves, and the replacement
    /// proof is verified against it.
    pub(crate) fn evict_cached_tree_update(
        &mut self,
        zkp_batch_index: usize,
    ) -> Result<(), NullifierTreeError> {
        self.cache_tree_update(zkp_batch_index, CachedTreeUpdate::default())
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
    pub(crate) fn checked_state(&self) -> Result<BatchState, NullifierTreeError> {
        self.try_get_state()
            .ok_or(NullifierTreeError::InvalidBatchState)
    }

    pub fn reclaimable_sequence(&self) -> Result<u64, NullifierTreeError> {
        self.start_index
            .checked_add(self.batch_size)
            .and_then(|end| end.checked_sub(1))
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    pub fn is_reclaimable(&self, close_before_index: u64) -> bool {
        self.reclaimable_sequence()
            .is_ok_and(|sequence| close_before_index >= sequence)
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    /// `start_index` is the first queue index covered by the reused batch.
    pub fn advance_state_to_fill(&mut self, start_index: u64) -> Result<(), NullifierTreeError> {
        if self.checked_state()? != BatchState::Inserted {
            #[cfg(feature = "log")]
            solana_msg::msg!(
                "Batch is in incorrect state {} expected BatchState::Inserted 1",
                self.state
            );
            return Err(NullifierTreeError::BatchNotReady);
        }
        self.reset(self.batch_size, self.zkp_batch_size, start_index);
        Ok(())
    }

    /// Prepares the batch to take another value. An inserted batch is reused for
    /// the next queue range, which starts `rotation` indices after its previous
    /// start. A full batch cannot take values until it is inserted into the tree.
    pub(crate) fn ensure_ready_to_fill(&mut self, rotation: u64) -> Result<(), NullifierTreeError> {
        match self.checked_state()? {
            BatchState::Fill => Ok(()),
            BatchState::Inserted => {
                let start_index = self
                    .start_index
                    .checked_add(rotation)
                    .ok_or(NullifierTreeError::ArithmeticOverflow)?;
                self.advance_state_to_fill(start_index)
            }
            BatchState::Full => {
                #[cfg(feature = "log")]
                solana_msg::msg!("current batch {:?} is full", self);
                Err(NullifierTreeError::BatchNotReady)
            }
        }
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    pub fn advance_state_to_inserted(&mut self) -> Result<(), NullifierTreeError> {
        if self.checked_state()? == BatchState::Full {
            self.state = BatchState::Inserted.into();
        } else {
            #[cfg(feature = "log")]
            solana_msg::msg!(
                "Batch is in incorrect state {} expected BatchState::Full 2",
                self.state
            );
            return Err(NullifierTreeError::BatchNotReady);
        }
        Ok(())
    }

    /// fill -> full -> inserted -> fill
    /// (from tree insertion perspective is pending if fill or full)
    pub fn advance_state_to_full(&mut self) -> Result<(), NullifierTreeError> {
        if self.checked_state()? == BatchState::Fill {
            self.state = BatchState::Full.into();
        } else {
            #[cfg(feature = "log")]
            solana_msg::msg!(
                "Batch is in incorrect state {} expected BatchState::Fill 0",
                self.state
            );
            return Err(NullifierTreeError::BatchNotReady);
        }
        Ok(())
    }

    pub fn get_first_ready_zkp_batch(&self) -> Result<u64, NullifierTreeError> {
        if self.checked_state()? == BatchState::Inserted {
            Err(NullifierTreeError::BatchAlreadyInserted)
        } else if self.batch_is_ready_to_insert() {
            Ok(self.num_inserted_zkp_batches)
        } else {
            Err(NullifierTreeError::BatchNotReady)
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
    pub fn add_to_hash_chain(&mut self, value: &[u8; 32]) -> Result<(), NullifierTreeError> {
        // 1. Check that the batch is ready.
        if self.checked_state()? != BatchState::Fill {
            return Err(NullifierTreeError::BatchNotReady);
        }
        let hash_chain_index = self.num_full_zkp_batches as usize;
        let start_new_hash_chain = self.num_inserted == 0;
        let hash_chain = if start_new_hash_chain {
            // 2. Start a new hash chain.
            *value
        } else {
            // 3. Add value to last hash chain.
            let existing = self
                .hash_chains
                .get(hash_chain_index)
                .ok_or(NullifierTreeError::HashChainFull)?;
            Poseidon::hashv(&[existing.as_slice(), value.as_slice()])?
        };
        let slot = self
            .hash_chains
            .get_mut(hash_chain_index)
            .ok_or(NullifierTreeError::HashChainFull)?;
        *slot = hash_chain;
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
    pub fn mark_as_inserted_in_merkle_tree(&mut self) -> Result<BatchState, NullifierTreeError> {
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

/// Direct access to the private counters so integration tests can drive a batch
/// into states the public transitions reach only after many insertions. Gated on
/// `test-only`, which the on-chain build never enables.
#[cfg(feature = "test-only")]
impl<const ZKP: usize> Batch<ZKP> {
    /// Builds a batch by value, which integration tests need to compare against
    /// an in-place initialized one.
    pub fn new(batch_size: u64, zkp_batch_size: u64, start_index: u64) -> Self {
        let mut batch = Self::new_zeroed();
        batch.init(batch_size, zkp_batch_size, start_index);
        batch
    }

    pub fn set_hash_chain(&mut self, zkp_batch_index: usize, value: [u8; 32]) {
        *self
            .hash_chains
            .get_mut(zkp_batch_index)
            .expect("zkp batch index out of range") = value;
    }

    pub fn set_cached_tree_update(&mut self, zkp_batch_index: usize, update: CachedTreeUpdate) {
        *self
            .cached_tree_updates
            .get_mut(zkp_batch_index)
            .expect("zkp batch index out of range") = update;
    }

    pub fn num_inserted(&self) -> u64 {
        self.num_inserted
    }

    pub fn set_num_inserted(&mut self, value: u64) {
        self.num_inserted = value;
    }

    pub fn set_state(&mut self, state: BatchState) {
        self.state = state.into();
    }

    /// Writes the raw state word, including values no `BatchState` maps to, so
    /// tests can assert that corrupt account data errors instead of panicking.
    pub fn set_raw_state(&mut self, state: u64) {
        self.state = state;
    }

    pub fn num_full_zkp_batches(&self) -> u64 {
        self.num_full_zkp_batches
    }

    pub fn set_num_full_zkp_batches(&mut self, value: u64) {
        self.num_full_zkp_batches = value;
    }

    pub fn set_num_inserted_zkp_batches(&mut self, value: u64) {
        self.num_inserted_zkp_batches = value;
    }
}
