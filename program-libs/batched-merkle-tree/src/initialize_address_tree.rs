use crate::{
    constants::{
        DEFAULT_ADDRESS_BATCH_SIZE, DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
        DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
    },
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
