use solana_address::Address;
use zolana_client::rpc::{MerkleContext, MerkleProof, STATE_TREE_HEIGHT};

/// The root `leaf` reaches alone at index 0, every sibling zero.
pub fn lone_root(leaf: [u8; 32]) -> [u8; 32] {
    MerkleProof {
        leaf,
        merkle_context: MerkleContext {
            tree_type: 0,
            tree: Address::default(),
        },
        path: vec![[0; 32]; STATE_TREE_HEIGHT],
        leaf_index: 0,
        root: [0; 32],
        root_seq: 0,
        root_index: 0,
    }
    .path_root()
    .expect("state root")
}
