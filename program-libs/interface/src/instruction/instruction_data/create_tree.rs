#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateTreeData {
    pub owner: [u8; 32],
}
