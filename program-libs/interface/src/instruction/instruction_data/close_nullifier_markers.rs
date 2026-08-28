#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseNullifierMarkersData {
    pub nullifiers: Vec<[u8; 32]>,
}
