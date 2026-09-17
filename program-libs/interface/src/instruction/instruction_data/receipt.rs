use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use super::merge_transact::MergeProof;

/// Public-input-hash domain of the receipt circuit
/// (`prover/server/circuits/nullifier_receipt`): folded first, then tree id,
/// nullifier root, count and the nullifier hash chain.
pub const RECEIPT_DOMAIN: u32 = 0x4e52_5031;

/// Accounts: rent payer (signer, becomes `rent_sponsor`), receipt (writable),
/// tree (read-only, bound into the receipt), system program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateReceiptData {
    pub nonce: u64,
    pub capacity: u16,
}

impl CreateReceiptData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Accounts: rent sponsor (signer), receipt (writable). Appends `nullifiers`
/// at slot `offset`, which must equal the slots filled so far.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UploadReceiptData {
    pub offset: u16,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
}

impl UploadReceiptData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Accounts: receipt (writable), tree (read-only). Permissionless: the proof
/// is over public data. `count` live slots must be filled and the remaining
/// slots zero; the proof's root is the tree's nullifier root at
/// `nullifier_tree_root_index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct VerifyReceiptData {
    pub nullifier_tree_root_index: u16,
    pub count: u16,
    pub proof: MergeProof,
    /// BSB22 commitment and its proof of knowledge, compressed G1.
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

impl VerifyReceiptData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}
