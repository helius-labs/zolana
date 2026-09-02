#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use zolana_tree::NullifierTreeInitParams;

#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreateTreeData {
    pub tree_id: u16,
    pub nullifier_params: NullifierTreeInitParams,
}
