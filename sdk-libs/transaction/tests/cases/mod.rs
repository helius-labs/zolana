/// Raw id of the tree these cases hash UTXOs under. The SDK reads a single
/// tree today; the id only has to match between the hash and the tree the
/// commitment lands in.
pub(crate) const TEST_TREE_ID: u16 = 0;

pub(crate) mod asset;
pub(crate) mod blinding;
pub(crate) mod common;
pub(crate) mod merge_derivation;
pub(crate) mod plaintext_transfer;
pub(crate) mod remote_authority;
pub(crate) mod serialization;
pub(crate) mod split;
pub(crate) mod transfer;
pub(crate) mod utxo;
pub(crate) mod utxo_encryption;
pub(crate) mod wallet;
