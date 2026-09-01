use std::pin::Pin;

use futures::Stream;
use solana_address::Address;
use solana_signature::Signature;
pub use zolana_indexer_api::{
    GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse,
    GetRingSpendRecordResponse, RingMemberProofRequest, RingSpendRecord, RingSpendRecordRequest,
};
use zolana_keypair::P256Pubkey;
pub use zolana_transaction::{OutputContext, OutputSlot, ShieldedTransaction};

use crate::{error::ClientError, prover::ProofCompressed};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub block_time: i64,
    /// Highest slot the indexer has persisted.
    pub slot: u64,
}

/// Identifies the tree a proof was produced against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleContext {
    pub tree_type: u16,
    pub tree: Address,
}

/// A single ciphertext whose view tag matched a query tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedUtxoMatch {
    pub slot: u64,
    pub tx_signature: Signature,
    pub output_slot: OutputSlot,
    /// `None` when the payload is plaintext (nothing to decrypt).
    pub tx_viewing_pk: Option<P256Pubkey>,
    /// Transaction-level AES salt shared by every output ciphertext; `None` for
    /// plaintext/proofless payloads.
    pub salt: Option<[u8; 16]>,
}

/// One transaction's place in the total order every rings stream shares.
///
/// Ordered by `(slot, signature)`, matching the indexer's pagination. Record a
/// position only once every row of that transaction has been applied, a resume
/// returns rows strictly after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainPosition {
    pub slot: u64,
    pub signature: Signature,
}

impl Ord for ChainPosition {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.slot, self.signature.as_ref()).cmp(&(other.slot, other.signature.as_ref()))
    }
}

impl PartialOrd for ChainPosition {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetEncryptedUtxosByTagsResponse {
    pub context: Context,
    /// Where the indexer says a new output should be appended. A property of
    /// the pool rather than of any match, so it is reported even for an empty
    /// page: a wallet that has never transacted learns its output tree from
    /// the same sync.
    ///
    /// `None` when the indexer has no answer -- every tree paused, or tree
    /// metadata not yet synced. A caller that needs an output tree refuses
    /// here rather than picking an id.
    pub output_tree_id: Option<u16>,
    pub matches: Vec<EncryptedUtxoMatch>,
    pub next: Option<ChainPosition>,
    pub latest: Option<ChainPosition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetShieldedTransactionsByTagsResponse {
    pub context: Context,
    /// As on [`GetEncryptedUtxosByTagsResponse`].
    pub output_tree_id: Option<u16>,
    pub transactions: Vec<ShieldedTransaction>,
    /// Last returned transaction when the limit truncated the scan.
    pub next: Option<ChainPosition>,
    /// Stream tip at the snapshot on a terminal page, including an empty one.
    pub latest: Option<ChainPosition>,
}

/// Page through every shielded transaction emitted by one custom ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingHistoryOptions {
    pub ring_program_id: Address,
    pub since: Option<ChainPosition>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedShieldedTransaction {
    pub event_index: u16,
    pub transaction: ShieldedTransaction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetShieldedTransactionsBySignatureResponse {
    pub context: Context,
    /// As on [`GetEncryptedUtxosByTagsResponse`].
    pub output_tree_id: Option<u16>,
    pub transactions: Vec<IndexedShieldedTransaction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetShieldedTransactionsByNullifiersResponse {
    pub context: Context,
    /// As on [`GetEncryptedUtxosByTagsResponse`].
    pub output_tree_id: Option<u16>,
    pub transactions: Vec<ShieldedTransaction>,
    /// Last returned transaction when the limit truncated the scan.
    pub next: Option<ChainPosition>,
    /// Stream tip on a terminal page. An unspent nullifier matches nothing, so
    /// this is its only resume point.
    pub latest: Option<ChainPosition>,
}

/// Stream of shielded transactions pushed as they land, one per matching transaction.
pub type ShieldedTransactionStream =
    Pin<Box<dyn Stream<Item = Result<ShieldedTransaction, ClientError>> + Send>>;

/// Inclusion proof for a leaf, plus the root metadata the consuming instruction needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub merkle_context: MerkleContext,
    /// Sibling hashes; length matches the tree height.
    pub path: Vec<[u8; 32]>,
    pub leaf_index: u64,
    pub root: [u8; 32],
    /// Completed Solana slot for ordering and freshness of a state-tree proof.
    pub root_seq: u64,
    /// Actual on-chain cyclic-history position for `root`; it is not derived
    /// from `root_seq` because slots without a tree update consume no entry.
    pub root_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetMerkleProofsResponse {
    pub context: Context,
    pub proofs: Vec<MerkleProof>,
}

/// Non-inclusion proof for a leaf against an indexed Merkle tree, with the low/high
/// adjacency witness bounding the exclusion range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonInclusionProof {
    pub leaf: [u8; 32],
    pub merkle_context: MerkleContext,
    pub path: Vec<[u8; 32]>,
    pub low_element: [u8; 32],
    pub low_element_index: u64,
    pub high_element: [u8; 32],
    pub high_element_index: u64,
    pub root: [u8; 32],
    /// On-chain indexed-tree update sequence.
    pub root_seq: u64,
    /// On-chain root-history position for `root`.
    pub root_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetNonInclusionProofsResponse {
    pub context: Context,
    pub proofs: Vec<NonInclusionProof>,
}

/// Result of a server-side proving request.
#[derive(Clone, Debug)]
pub struct ProveResult {
    pub proof: ProofCompressed,
    pub public_inputs: Vec<[u8; 32]>,
    pub circuit_id: u16,
}
