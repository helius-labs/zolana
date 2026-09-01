use borsh::{BorshDeserialize, BorshSerialize};

use crate::nullifier_tree::{
    constants::{
        ADDRESS_TREE_INIT_ROOT_40, DEFAULT_ADDRESS_BATCH_SIZE, DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
        DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
    },
    error::NullifierTreeError,
    layout::{NullifierTreeLayout, TreeType},
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct InitAddressTreeAccountsInstructionData {
    pub input_queue_batch_size: u64,
    pub input_queue_zkp_batch_size: u64,
    pub height: u32,
}

impl Default for InitAddressTreeAccountsInstructionData {
    fn default() -> Self {
        Self {
            input_queue_batch_size: DEFAULT_ADDRESS_BATCH_SIZE,
            input_queue_zkp_batch_size: DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
            height: DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
        }
    }
}

/// Only 10 and 250 are supported.
pub fn match_circuit_size(size: u64) -> bool {
    matches!(size, 10 | 250) // TODO: make these constants (10, 5000), 3 configs (local test (current local), devnet (5k proofs, 30k queue len), mainnet(5k proofs, 1.2mm queue len))
}

// TODO: rename ZKP -> ZKP_BATCH_SIZE
// TODO: rename AddressV2 -> NullifierTreeV1
impl<const ZKP: usize> NullifierTreeLayout<ZKP> {
    /// Initializes a zeroed layout in place.
    ///
    /// `address_init_root` is the init root for indexed (`AddressV2`) trees.
    /// `None` uses the default address sentinel root
    /// (`ADDRESS_TREE_INIT_ROOT_40`). Pass `Some` to seed an indexed tree with a
    /// different sentinel, e.g. the BN254 `p-1` nullifier-tree root
    /// (`NULLIFIER_TREE_INIT_ROOT_40`).
    pub fn init(
        &mut self,
        input_queue_batch_size: u64,
        input_queue_zkp_batch_size: u64,
        height: u32,
        tree_type: TreeType, // TODO: remove TreeType
        address_init_root: Option<[u8; 32]>,
    ) -> Result<(), NullifierTreeError> {
        Self::validate_configuration(input_queue_batch_size, input_queue_zkp_batch_size)?;
        let capacity = 1u64
            .checked_shl(height)
            .ok_or(NullifierTreeError::InvalidHeight)?;
        // Sanity check since init value is hardcoded. Gated on the test-only
        // feature, never enabled in the on-chain build, so tests can build
        // small trees while the program keeps the check.
        #[cfg(not(feature = "test-only"))]
        if height != 40 {
            return Err(NullifierTreeError::InvalidHeight);
        }

        // Written field by field: the layout carries both batches with their
        // hash chains and cached updates, which are too large to move through a
        // Solana stack frame as a struct literal.
        self.tree_type = tree_type as u64;
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
        self.queue_next_index = 0;
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

        // The initialized indexed Merkle tree contains two elements.
        // 1. element:
        // H(0, 1, 452312848583266388373324160190187140051835877600158453279131187530910662655)
        // 2. element:
        // H(452312848583266388373324160190187140051835877600158453279131187530910662655, 0, 0)
        // ... other elements: 0
        *self
            .root_history
            .roots
            .get_mut(0)
            .ok_or(NullifierTreeError::InvalidRootHistoryCapacity)? =
            address_init_root.unwrap_or(ADDRESS_TREE_INIT_ROOT_40);
        // The cursor wraps modulo ZKP so a single-slot root history seeds back
        // to index 0 instead of an out-of-range 1 that no load would accept.
        self.root_history.current_index = 1 % ZKP as u64;
        Ok(())
    }
}

#[cfg(feature = "test-only")]
pub mod test_utils {
    pub use super::InitAddressTreeAccountsInstructionData;
    use crate::nullifier_tree::constants::{TEST_DEFAULT_BATCH_SIZE, TEST_DEFAULT_ZKP_BATCH_SIZE};

    impl InitAddressTreeAccountsInstructionData {
        pub fn test_default() -> Self {
            Self {
                input_queue_batch_size: TEST_DEFAULT_BATCH_SIZE,
                input_queue_zkp_batch_size: TEST_DEFAULT_ZKP_BATCH_SIZE,
                height: 40,
            }
        }
    }
}
