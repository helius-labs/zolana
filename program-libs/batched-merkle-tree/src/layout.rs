use core::mem::{size_of, MaybeUninit};

use aligned_sized::aligned_sized;
use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    batch::{Batch, BatchState},
    constants::NUM_BATCHES,
    errors::NullifierTreeError,
    BorshDeserialize, BorshSerialize,
};

pub const ADDRESS_MERKLE_TREE_TYPE_V2: u64 = 4;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u64)]
pub enum TreeType {
    AddressV2 = ADDRESS_MERKLE_TREE_TYPE_V2,
}

#[repr(C)]
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Debug,
    PartialEq,
    Default,
    Clone,
    Copy,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
pub struct QueueBatches {
    /// Reserved account-layout field. Must contain [`NUM_BATCHES`] on load.
    pub reserved: u64,
    /// Number of elements in a batch.
    pub batch_size: u64,
    /// Number of elements in a ZKP batch.
    /// A batch has one or more ZKP batches.
    pub zkp_batch_size: u64,
    /// Batch elements are currently inserted in.
    pub currently_processing_batch_index: u64,
    /// Next batch to be inserted into the tree.
    pub pending_batch_index: u64,
    /// Output queues require next index to derive compressed account hashes.
    /// Output & Address queues append state hence need to check tree capacity.
    /// next_index in queue is ahead or equal to next index in the associated
    /// batched Merkle tree account.
    pub next_index: u64,
    pub batches: [Batch; 2],
}

impl QueueBatches {
    /// Returns the number of ZKP batches contained within a single regular batch.
    pub fn get_num_zkp_batches(&self) -> u64 {
        self.batch_size / self.zkp_batch_size
    }

    /// Queue indices covered by one pass over all batches. A batch reaches
    /// Inserted only after exactly batch_size insertions, so on reuse its
    /// coverage starts one full rotation after its previous start. Nothing in
    /// verify/apply reads batch start_index (the proof StartIndex is derived
    /// from the tree next index); it is kept correct for indexers.
    pub fn rotation(&self) -> Result<u64, NullifierTreeError> {
        (NUM_BATCHES as u64)
            .checked_mul(self.batch_size)
            .ok_or(NullifierTreeError::ArithmeticOverflow)
    }

    pub fn get_current_batch(&self) -> Result<&Batch, NullifierTreeError> {
        self.batches
            .get(self.currently_processing_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    pub fn get_current_batch_mut(&mut self) -> Result<&mut Batch, NullifierTreeError> {
        self.batches
            .get_mut(self.currently_processing_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    /// Validates the queue, root-history, and cached-update capacities together.
    /// A root is appended for each ZKP batch, so one queue batch must contain
    /// exactly as many ZKP batches as both fixed-size account regions can hold.
    pub fn validate_configuration<const ZKP: usize>(
        batch_size: u64,
        zkp_batch_size: u64,
    ) -> Result<(), NullifierTreeError> {
        if batch_size == 0 || zkp_batch_size == 0 || !batch_size.is_multiple_of(zkp_batch_size) {
            return Err(NullifierTreeError::BatchSizeNotDivisibleByZkpBatchSize);
        }

        if batch_size / zkp_batch_size != ZKP as u64 {
            return Err(NullifierTreeError::InvalidRootHistoryCapacity);
        }
        Ok(())
    }

    /// Initializes all queue metadata and both batches from an already
    /// validated configuration.
    pub(crate) fn new(
        batch_size: u64,
        zkp_batch_size: u64,
        start_index: u64,
    ) -> Result<Self, NullifierTreeError> {
        let second_batch_start_index = start_index
            .checked_add(batch_size)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;

        Ok(QueueBatches {
            reserved: NUM_BATCHES as u64,
            zkp_batch_size,
            batch_size,
            currently_processing_batch_index: 0,
            pending_batch_index: 0,
            next_index: 0,
            batches: [
                Batch::new(batch_size, zkp_batch_size, start_index),
                Batch::new(batch_size, zkp_batch_size, second_batch_start_index),
            ],
        })
    }

    /// Validated counterpart to [`new`](Self::new) for integration tests, which
    /// cannot reach the crate-private constructor. Gated on `test-only`, which
    /// the on-chain build never enables.
    #[cfg(feature = "test-only")]
    pub fn new_validated<const ZKP: usize>(
        batch_size: u64,
        zkp_batch_size: u64,
        start_index: u64,
    ) -> Result<Self, NullifierTreeError> {
        Self::validate_configuration::<ZKP>(batch_size, zkp_batch_size)?;
        Self::new(batch_size, zkp_batch_size, start_index)
    }

    /// Increment the next full batch index if current state is BatchState::Inserted.
    pub fn increment_pending_batch_index_if_inserted(&mut self, state: BatchState) {
        if state == BatchState::Inserted {
            self.pending_batch_index = (self.pending_batch_index + 1) % NUM_BATCHES as u64;
        }
    }

    /// Increment the currently_processing_batch_index if current state is BatchState::Full.
    pub fn increment_currently_processing_batch_index_if_full(
        &mut self,
    ) -> Result<(), NullifierTreeError> {
        let state = self.get_current_batch()?.checked_state()?;
        if state == BatchState::Full {
            self.currently_processing_batch_index =
                (self.currently_processing_batch_index + 1) % NUM_BATCHES as u64;
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    PartialEq,
    Clone,
    Copy,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
#[aligned_sized(anchor)]
pub struct BatchedMerkleTreeMetadata {
    pub tree_type: u64,
    pub sequence_number: u64,
    pub next_index: u64,
    pub height: u32,
    /// Root-history capacity is the `ZKP` const generic (`batch_size /
    /// zkp_batch_size`), so it is not stored. `bytemuck::Pod` forbids implicit
    /// padding, so the four bytes it used to occupy are declared explicitly.
    pub _padding: [u8; 4],
    pub capacity: u64,
    pub queue_batches: QueueBatches,
    pub close_before_index: u64,
}

/// Cyclic root-history region: a write cursor followed by `N` root slots.
/// Capacity is the const generic `N`, so the only stored word is the cursor.
/// `[u8; 32]` is align-1, so there is no padding between the cursor and the
/// roots; the region is 8-byte aligned because the cursor is a `u64`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RootHistory<const N: usize> {
    pub current_index: u64,
    pub roots: [[u8; 32]; N],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CachedTreeUpdate {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub occupied: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NullifierTreeLayout<const ZKP_BATCHES: usize> {
    pub metadata: BatchedMerkleTreeMetadata,
    pub root_history: RootHistory<ZKP_BATCHES>,
    pub hash_chains: [[[u8; 32]; ZKP_BATCHES]; NUM_BATCHES],
    pub cached_tree_updates: [[CachedTreeUpdate; ZKP_BATCHES]; NUM_BATCHES],
}

unsafe impl<C: ConfigCore, const ZKP: usize> ZeroCopy<C> for NullifierTreeLayout<ZKP> {}

unsafe impl<'de, C: ConfigCore, const ZKP: usize> SchemaRead<'de, C> for NullifierTreeLayout<ZKP> {
    type Dst = Self;
    const TYPE_META: TypeMeta = TypeMeta::Static {
        size: size_of::<Self>(),
        zero_copy: true,
    };

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self>) -> ReadResult<()> {
        unsafe { Ok(reader.copy_into_t(dst)?) }
    }
}
