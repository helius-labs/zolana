use solana_address::Address as Pubkey;

use crate::{
    constants::{
        DEFAULT_ADDRESS_BATCH_SIZE, DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
        DEFAULT_BATCH_ADDRESS_TREE_HEIGHT, NULLIFIER_TREE_INIT_ROOT_40,
    },
    errors::BatchedMerkleTreeError,
    merkle_tree::BatchedMerkleTreeAccount,
    merkle_tree_metadata::TreeType,
    zero_copy::TreeAccountLayout,
    BorshDeserialize, BorshSerialize,
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

/// Initializes a batched nullifier Merkle tree directly into a typed
/// [`TreeAccountLayout`], seeding it with the BN254 `p-1` sentinel root
/// ([`NULLIFIER_TREE_INIT_ROOT_40`]). Used by callers that hold a typed layout
/// view (e.g. a combined account layout) instead of a raw byte slice.
pub fn init_batched_nullifier_merkle_tree_into_layout<const ZKP: usize>(
    params: InitAddressTreeAccountsInstructionData,
    layout: &mut TreeAccountLayout<ZKP>,
    pubkey: Pubkey,
) -> Result<BatchedMerkleTreeAccount<'_, ZKP>, BatchedMerkleTreeError> {
    BatchedMerkleTreeAccount::init_from_layout(
        layout,
        &pubkey,
        params.input_queue_batch_size,
        params.input_queue_zkp_batch_size,
        params.height,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
}

/// Only 10 and 250 are supported.
pub fn match_circuit_size(size: u64) -> bool {
    matches!(size, 10 | 250)
}

#[cfg(feature = "test-only")]
pub mod test_utils {
    pub use super::InitAddressTreeAccountsInstructionData;
    use crate::constants::{TEST_DEFAULT_BATCH_SIZE, TEST_DEFAULT_ZKP_BATCH_SIZE};

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
