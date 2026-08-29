use core::mem::{offset_of, size_of, MaybeUninit};

use wincode::{
    config::{ConfigCore, ZeroCopy},
    io::Reader,
    ReadResult, SchemaRead, TypeMeta,
};
#[cfg(feature = "test-only")]
use zerocopy::FromZeros;
use zerocopy::{FromBytes, Immutable, KnownLayout};

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
    Clone,
    Copy,
    FromBytes,
    KnownLayout,
    Immutable,
)]
pub struct QueueBatches<const ZKP: usize> {
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
    pub batches: [Batch<ZKP>; NUM_BATCHES],
}

impl<const ZKP: usize> QueueBatches<ZKP> {
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

    pub fn get_current_batch(&self) -> Result<&Batch<ZKP>, NullifierTreeError> {
        self.batches
            .get(self.currently_processing_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    pub fn get_current_batch_mut(&mut self) -> Result<&mut Batch<ZKP>, NullifierTreeError> {
        self.batches
            .get_mut(self.currently_processing_batch_index as usize)
            .ok_or(NullifierTreeError::InvalidBatchIndex)
    }

    /// Validates the queue, root-history, and cached-update capacities together.
    /// A root is appended for each ZKP batch, so one queue batch must contain
    /// exactly as many ZKP batches as both fixed-size account regions can hold.
    pub fn validate_configuration(
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
    /// validated configuration. Writes in place: a queue carries both batches'
    /// hash chains, which are too large to move through a Solana stack frame.
    pub(crate) fn init(
        &mut self,
        batch_size: u64,
        zkp_batch_size: u64,
        start_index: u64,
    ) -> Result<(), NullifierTreeError> {
        let second_batch_start_index = start_index
            .checked_add(batch_size)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;

        self.reserved = NUM_BATCHES as u64;
        self.batch_size = batch_size;
        self.zkp_batch_size = zkp_batch_size;
        self.currently_processing_batch_index = 0;
        self.pending_batch_index = 0;
        self.next_index = 0;
        for (batch, batch_start_index) in self
            .batches
            .iter_mut()
            .zip([start_index, second_batch_start_index])
        {
            batch.init(batch_size, zkp_batch_size, batch_start_index);
        }
        Ok(())
    }

    /// Validated counterpart to [`init`](Self::init) that returns a queue by
    /// value, which integration tests need. Gated on `test-only`, which the
    /// on-chain build never enables.
    #[cfg(feature = "test-only")]
    pub fn new_validated(
        batch_size: u64,
        zkp_batch_size: u64,
        start_index: u64,
    ) -> Result<Self, NullifierTreeError> {
        Self::validate_configuration(batch_size, zkp_batch_size)?;
        let mut queue = Self::new_zeroed();
        queue.init(batch_size, zkp_batch_size, start_index)?;
        Ok(queue)
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

/// `QueueBatches` is `repr(C)` without implicit padding, for every `ZKP`; two
/// instantiations pin the size formula.
const _: () = {
    assert!(size_of::<QueueBatches<1>>() == 48 + NUM_BATCHES * size_of::<Batch<1>>());
    assert!(size_of::<QueueBatches<9>>() == 48 + NUM_BATCHES * size_of::<Batch<9>>());
};

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
    pub tree_type: u64,
    pub sequence_number: u64,
    pub next_index: u64,
    pub height: u32,
    /// Root-history capacity is the `ZKP_BATCHES` const generic (`batch_size /
    /// zkp_batch_size`), so it is not stored. The account layout admits no
    /// implicit padding, so the four bytes it used to occupy are declared
    /// explicitly.
    pub _padding: [u8; 4],
    pub capacity: u64,
    pub queue_batches: QueueBatches<ZKP_BATCHES>,
    pub close_before_index: u64,
    pub root_history: RootHistory<ZKP_BATCHES>,
    pub cached_tree_updates: [[CachedTreeUpdate; ZKP_BATCHES]; NUM_BATCHES],
}

/// The account layout admits no implicit padding between regions: the header
/// words are 8-aligned, `QueueBatches` is a multiple of 8, and the root history
/// opens with an 8-aligned cursor. Two instantiations pin the region offsets.
const _: () = {
    assert!(offset_of!(NullifierTreeLayout<1>, queue_batches) == 40);
    assert!(offset_of!(NullifierTreeLayout<9>, queue_batches) == 40);
    assert!(offset_of!(NullifierTreeLayout<1>, root_history) == 48 + size_of::<QueueBatches<1>>());
    assert!(offset_of!(NullifierTreeLayout<9>, root_history) == 48 + size_of::<QueueBatches<9>>());
    assert!(
        offset_of!(NullifierTreeLayout<1>, cached_tree_updates)
            == 48 + size_of::<QueueBatches<1>>() + size_of::<RootHistory<1>>()
    );
    assert!(
        offset_of!(NullifierTreeLayout<9>, cached_tree_updates)
            == 48 + size_of::<QueueBatches<9>>() + size_of::<RootHistory<9>>()
    );
};

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
