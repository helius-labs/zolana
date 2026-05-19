use borsh::{BorshDeserialize, BorshSerialize};

/// Parameters for `create_pool_tree`. The two sub-tree shapes (state height,
/// address-tree default config) are currently fixed by the shielded-pool
/// program; this struct is intentionally empty as a forward-compatibility
/// placeholder.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreatePoolTreeData;
