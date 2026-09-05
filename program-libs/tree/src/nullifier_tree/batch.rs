use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "test-only")]
use zerocopy::FromZeros;
use zerocopy::{FromBytes, Immutable, KnownLayout};
use zolana_hasher::{Hasher, Poseidon};

use crate::nullifier_tree::{constants::NUM_BATCHES, error::NullifierTreeError};

/// Transitions: `Fill -> Full -> Inserted -> Fill`. From the tree's
/// perspective a batch is pending while `Fill` or `Full`.
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[repr(u64)]
pub enum BatchState {
    Fill,
    Inserted,
    Full,
}

impl TryFrom<u64> for BatchState {
    type Error = NullifierTreeError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BatchState::Fill),
            1 => Ok(BatchState::Inserted),
            2 => Ok(BatchState::Full),
            _ => Err(NullifierTreeError::InvalidBatchState),
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

/// One of the queue's two batches: its counters, state, hash chains, and
/// cached tree updates. It is applied to the tree one ZKP batch at a time.
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
pub struct Batch<const ZKP_BATCHES: usize> {
    /// Elements in the ZKP batch currently being filled.
    num_inserted: u64,
    state: u64,
    /// ZKP batches whose hash chain is complete.
    pub(crate) num_full_zkp_batches: u64,
    /// ZKP batches applied to the tree.
    num_inserted_zkp_batches: u64,
    pub batch_size: u64,
    pub zkp_batch_size: u64,
    /// Leaf index of the batch's first element.
    pub start_index: u64,
    /// One Poseidon hash chain per ZKP batch. The chain at
    /// `num_full_zkp_batches` is the one insertions currently extend; the
    /// chains below it are complete and are the prover inputs of the pending
    /// tree updates.
    hash_chains: [[u8; 32]; ZKP_BATCHES],
    /// One cached tree update per ZKP batch, verified and waiting to be applied
    /// to the tree. The slot at `num_inserted_zkp_batches` is the next update
    /// that can be applied; a slot is cleared once its update is in the tree.
    cached_tree_updates: [CachedTreeUpdate; ZKP_BATCHES],
}

impl<const ZKP_BATCHES: usize> Batch<ZKP_BATCHES> {
    /// Initializes a batch in place. Requires zeroed account data: the hash
    /// chains and cached updates are not written here.
    pub(crate) fn init(&mut self, batch_size: u64, zkp_batch_size: u64, start_index: u64) {
        self.reset(batch_size, zkp_batch_size, start_index);
    }

    /// Resets the counters and state so a reused batch inherits nothing from
    /// its previous queue range. The hash chains and cached updates need no
    /// zeroing: a filling batch writes a chain slot before reading it, and
    /// `clear_cached_tree_update` zeroes each slot pair as its update lands in
    /// the tree, so a batch reaches `Inserted` with both arrays zeroed.
    fn reset(&mut self, batch_size: u64, zkp_batch_size: u64, start_index: u64) {
        self.num_inserted = 0;
        self.state = BatchState::Fill.into();
        self.num_full_zkp_batches = 0;
        self.num_inserted_zkp_batches = 0;
        self.batch_size = batch_size;
        self.zkp_batch_size = zkp_batch_size;
        self.start_index = start_index;
    }

    /// Returns the complete or in-progress hash chain of a ZKP batch.
    pub fn hash_chain(&self, zkp_batch_index: usize) -> Option<[u8; 32]> {
        self.hash_chains.get(zkp_batch_index).copied()
    }

    /// Number of cached update slots, one per ZKP batch.
    pub fn num_zkp_batches(&self) -> usize {
        self.hash_chains.len()
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
            .ok_or(NullifierTreeError::ZkpBatchIndexOutOfRange)? = update;
        Ok(())
    }

    /// Clears an applied ZKP batch's slots: the cached update (`occupied = 0`)
    /// and the hash chain it was verified against, which is dead once the
    /// update is in the tree.
    pub(crate) fn clear_cached_tree_update(
        &mut self,
        zkp_batch_index: usize,
    ) -> Result<(), NullifierTreeError> {
        self.evict_cached_tree_update(zkp_batch_index)?;
        *self
            .hash_chains
            .get_mut(zkp_batch_index)
            .ok_or(NullifierTreeError::ZkpBatchIndexOutOfRange)? = [0u8; 32];
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

    pub fn get_state(&self) -> Result<BatchState, NullifierTreeError> {
        self.state.try_into()
    }

    /// Exclusive leaf index just past the batch's last element.
    pub fn end_index(&self) -> Result<u64, NullifierTreeError> {
        self.start_index
            .checked_add(self.batch_size)
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    /// Every PDA of the batch is closable once the watermark has passed its
    /// last element.
    pub fn is_reclaimable(&self, close_before_index: u64) -> bool {
        self.end_index()
            .is_ok_and(|end_index| close_before_index >= end_index)
    }

    /// `start_index` is the leaf index of the reused batch's first element.
    pub fn advance_state_to_fill(&mut self, start_index: u64) -> Result<(), NullifierTreeError> {
        if self.get_state()? != BatchState::Inserted {
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

    pub(crate) fn ensure_ready_to_fill(
        &mut self,
        batch_size: u64,
    ) -> Result<(), NullifierTreeError> {
        match self.get_state()? {
            BatchState::Fill => Ok(()),
            BatchState::Inserted => {
                let rotation = batch_size
                    .checked_mul(NUM_BATCHES as u64)
                    .ok_or(NullifierTreeError::ArithmeticOverflow)?;
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

    pub fn advance_state_to_inserted(&mut self) -> Result<(), NullifierTreeError> {
        if self.get_state()? == BatchState::Full {
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

    pub fn advance_state_to_full(&mut self) -> Result<(), NullifierTreeError> {
        if self.get_state()? == BatchState::Fill {
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
        if self.get_state()? == BatchState::Inserted {
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

    pub fn get_num_ready_zkp_updates(&self) -> u64 {
        self.num_full_zkp_batches
            .saturating_sub(self.num_inserted_zkp_batches)
    }

    /// Index of the ZKP batch new values are inserted into.
    pub fn get_current_zkp_batch_index(&self) -> u64 {
        self.num_full_zkp_batches
    }

    pub fn get_num_inserted_zkps(&self) -> u64 {
        self.num_inserted_zkp_batches
    }

    pub fn get_num_inserted_elements(&self) -> Result<u64, NullifierTreeError> {
        self.num_full_zkp_batches
            .checked_mul(self.zkp_batch_size)
            .and_then(|inserted| inserted.checked_add(self.num_inserted))
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    pub const fn get_num_zkp_batches(&self) -> u64 {
        ZKP_BATCHES as u64
    }

    /// Add a value to the current hash chain, and advance batch state.
    /// Does not mutate on error: all of its failure points (batch state, store
    /// capacity, hashing) precede the write.
    /// 1. Check that the batch is ready.
    /// 2. If the zkp batch is empty, start a new hash chain.
    /// 3. If the zkp batch is not empty, add value to last hash chain.
    /// 4. If the zkp batch is full, increment the zkp batch index.
    /// 5. If all zkp batches are full, set batch state to full.
    pub fn add_to_hash_chain(&mut self, value: &[u8; 32]) -> Result<(), NullifierTreeError> {
        // 1. Check that the batch is ready.
        if self.get_state()? != BatchState::Fill {
            return Err(NullifierTreeError::BatchNotReady);
        }
        if self.zkp_batch_size == 0 || self.num_inserted >= self.zkp_batch_size {
            return Err(NullifierTreeError::InvalidBatchConfiguration);
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
        let current_hash_chain = self
            .hash_chains
            .get_mut(hash_chain_index)
            .ok_or(NullifierTreeError::HashChainFull)?;
        *current_hash_chain = hash_chain;
        self.num_inserted = self
            .num_inserted
            .checked_add(1)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;

        // 4. If the zkp batch is full, increment the zkp batch index.
        let zkp_batch_is_full = self.num_inserted == self.zkp_batch_size;
        if zkp_batch_is_full {
            self.num_full_zkp_batches = self
                .num_full_zkp_batches
                .checked_add(1)
                .ok_or(NullifierTreeError::ArithmeticOverflow)?;
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

    /// Marks the next zkp batch as inserted in the merkle tree; the batch
    /// becomes `Inserted` once the last one is.
    /// 1. Checks that the batch is ready.
    /// 2. increments the number of inserted zkps.
    /// 3. If all zkps are inserted, sets the state to inserted.
    /// 4. Returns the updated state of the batch.
    pub fn mark_as_inserted_in_merkle_tree(&mut self) -> Result<BatchState, NullifierTreeError> {
        // 1. Check that batch is ready.
        self.get_first_ready_zkp_batch()?;

        let num_zkp_batches = self.get_num_zkp_batches();

        // 2. increments the number of inserted zkps.
        self.num_inserted_zkp_batches = self
            .num_inserted_zkp_batches
            .checked_add(1)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;
        // 3. If all zkp batches are inserted, sets the state to inserted.
        let batch_is_completely_inserted = self.num_inserted_zkp_batches == num_zkp_batches;
        if batch_is_completely_inserted {
            self.advance_state_to_inserted()?;
        }

        self.get_state()
    }
}

/// Direct access to the private counters so integration tests can drive a batch
/// into states the public transitions reach only after many insertions.
#[cfg(feature = "test-only")]
impl<const ZKP_BATCHES: usize> Batch<ZKP_BATCHES> {
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
