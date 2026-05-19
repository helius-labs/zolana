use borsh::{BorshDeserialize, BorshSerialize};

/// On-chain layout of a shielded-pool tree account. A single Solana account
/// hosts both an append-only state sub-tree (sparse merkle) and a batched
/// address sub-tree (in-account input queue), co-located in one byte buffer.
///
/// This header is the client-side representation; the actual on-chain bytes
/// are written by the shielded-pool program in a fixed layout described in
/// `programs/shielded-pool/src/instructions/create_pool_tree/init.rs`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct PoolTreeHeader {
    pub authority: [u8; 32],
    pub merkle_tree: [u8; 32],
}
