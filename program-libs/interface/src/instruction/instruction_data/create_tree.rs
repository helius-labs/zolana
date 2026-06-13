use borsh::{BorshDeserialize, BorshSerialize};

/// Parameters for `create_tree`. The two sub-tree shapes (state height,
/// address-tree default config) are currently fixed by the shielded-pool
/// program, so this struct is intentionally empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreateTreeData;
