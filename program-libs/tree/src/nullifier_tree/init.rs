use borsh::{BorshDeserialize, BorshSerialize};

use crate::nullifier_tree::{
    constants::{
        DEFAULT_NULLIFIER_BATCH_SIZE, DEFAULT_NULLIFIER_TREE_HEIGHT,
        DEFAULT_NULLIFIER_ZKP_BATCH_SIZE, NULLIFIER_TREE_INIT_ROOT_40,
    },
    error::NullifierTreeError,
    layout::NullifierTreeLayout,
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NullifierTreeInitParams {
    pub input_queue_batch_size: u64,
    pub input_queue_zkp_batch_size: u64,
    pub height: u32,
}

impl Default for NullifierTreeInitParams {
    fn default() -> Self {
        Self {
            input_queue_batch_size: DEFAULT_NULLIFIER_BATCH_SIZE,
            input_queue_zkp_batch_size: DEFAULT_NULLIFIER_ZKP_BATCH_SIZE,
            height: DEFAULT_NULLIFIER_TREE_HEIGHT,
        }
    }
}

/// ZKP batch sizes a tree can be created with: the shapes that have a
/// committed verifying key (`batch_address_append_40_{10,250}`).
pub const SUPPORTED_ZKP_BATCH_SIZES: [u64; 2] = [10, 250];

/// Whether `hash_chain_4` folds `zkp_batch_size` values into full groups of
/// three. The first value seeds the chain and every later group of three is
/// absorbed with one Poseidon call, so the last group is full exactly when
/// `zkp_batch_size - 1` is a multiple of three.
///
/// A size that fails this still hashes correctly: the fold zero-pads the short
/// trailing group and `add_to_hash_chain` mirrors the padding. But the padded
/// fold is the one place where the chain is not injective across lengths
/// (`[a, b]` and `[a, b, 0, 0]` collide), so a tree that can be created on
/// chain must not need it.
pub const fn hash_chain_groups_are_full(zkp_batch_size: u64) -> bool {
    zkp_batch_size % 3 == 1
}

pub const fn match_circuit_size(size: u64) -> bool {
    let mut index = 0;
    // Const-evaluated indexing: an out-of-range index is a compile error here,
    // not a runtime panic.
    while index < SUPPORTED_ZKP_BATCH_SIZES.len() {
        if SUPPORTED_ZKP_BATCH_SIZES[index] == size {
            return true;
        }
        index += 1;
    }
    false
}

/// Every nullifier queued on chain is folded into its ZKP batch's hash chain,
/// and a tree can only be created with a supported size, so no reachable chain
/// may need padding. Adding a size that pads fails the build instead.
const _: () = {
    let mut index = 0;
    while index < SUPPORTED_ZKP_BATCH_SIZES.len() {
        assert!(
            hash_chain_groups_are_full(SUPPORTED_ZKP_BATCH_SIZES[index]),
            "a supported zkp batch size must fill every hash chain group"
        );
        index += 1;
    }
    assert!(
        match_circuit_size(DEFAULT_NULLIFIER_ZKP_BATCH_SIZE),
        "the default zkp batch size must be one a tree can be created with"
    );
};

impl<const ZKP_BATCHES: usize> NullifierTreeLayout<ZKP_BATCHES> {
    /// Initializes a zeroed layout in place, seeded with the BN254 `p-1`
    /// sentinel root (`NULLIFIER_TREE_INIT_ROOT_40`).
    pub fn init(
        &mut self,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
    ) -> Result<(), NullifierTreeError> {
        Self::validate_configuration(input_queue_batch_size, input_queue_zkp_batch_size)?;
        let capacity = 1u64
            .checked_shl(height)
            .ok_or(NullifierTreeError::InvalidHeight)?;
        // NULLIFIER_TREE_INIT_ROOT_40 is the root for height 40. The
        // `test-only` feature drops this check so tests can build small trees.
        #[cfg(not(feature = "test-only"))]
        if height != 40 {
            return Err(NullifierTreeError::InvalidHeight);
        }

        // Written field by field: the layout carries both batches with their
        // hash chains and cached updates, which are too large to move through a
        // Solana stack frame as a struct literal.
        self.sequence_number = 0;
        self.next_index = 1;
        self.height = height;
        self.capacity = capacity;
        self.close_before_index = 0;

        let second_batch_start_index = self
            .next_index
            .checked_add(input_queue_batch_size)
            .ok_or(NullifierTreeError::ArithmeticOverflow)?;

        self.batch_size = input_queue_batch_size;
        self.zkp_batch_size = input_queue_zkp_batch_size;
        self.currently_processing_batch_index = 0;
        self.pending_batch_index = 0;
        // A queue index is the leaf index its value takes once appended, so
        // the queue starts at the first free leaf and zero is never issued.
        self.queue_next_index = self.next_index;
        for (batch, batch_start_index) in self
            .batches
            .iter_mut()
            .zip([self.next_index, second_batch_start_index])
        {
            batch.init(
                input_queue_batch_size,
                input_queue_zkp_batch_size,
                batch_start_index,
            );
        }

        // The initialized tree holds one leaf, element 0 with `next_value` set
        // to the BN254 `p-1` sentinel, hence `next_index = 1` above.
        *self
            .root_history
            .roots
            .get_mut(0)
            .ok_or(NullifierTreeError::InvalidRootHistoryCapacity)? = NULLIFIER_TREE_INIT_ROOT_40;
        // Wraps so a single-slot root history (test-only) starts at 0, which
        // `validate` accepts.
        self.root_history.current_index = 1 % ZKP_BATCHES as u64;
        Ok(())
    }
}
