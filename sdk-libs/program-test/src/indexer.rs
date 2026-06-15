//! Test-side indexer for the shielded pool.
//!
//! A real indexer reads `ProoflessShieldEvent`s from `emit_event` inner
//! instructions (self-CPIs by the shielded-pool program) and tracks where
//! each deposit landed in the state tree. This replays the same events into
//! an in-memory reference tree, so tests can
//! - assert the on-chain state root matches an independent recomputation, and
//! - locate a deposited UTXO (leaf index + fields) the way a wallet would,
//!   without any decryption.

use light_hasher::Poseidon;
use light_merkle_tree_reference::MerkleTree;
use thiserror::Error;
use zolana_interface::{instruction::ProoflessShieldEvent, state::STATE_HEIGHT};
use zolana_transaction::{utxo_hash, Address, TransactionError};

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("transaction: {0}")]
    Transaction(#[from] TransactionError),
    #[error("event utxo_hash mismatch: expected {expected:?}, got {actual:?}")]
    UtxoHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("reference merkle tree: {0}")]
    MerkleTree(String),
}

/// One indexed shielded output, in the shape a real indexer serves to wallets
/// (cf. the client RPC `OutputSlot`): the recipient view tag it is scanned for,
/// its position in the state tree, the on-chain leaf, and a [`payload`] that is
/// either the public proofless fields or — once transfers exist — the encrypted
/// ciphertext the recipient decrypts. Every output, regardless of rail, shares
/// the same envelope so the indexer never branches on deposit kind for storage,
/// lookup, or root tracking.
///
/// [`payload`]: IndexedUtxo::payload
#[derive(Clone, Debug)]
pub struct IndexedUtxo {
    /// Recipient view tag the output is scanned for.
    pub view_tag: [u8; 32],
    /// Position of the leaf in the state tree.
    pub leaf_index: u64,
    /// The on-chain leaf (UTXO hash) appended to the tree.
    pub utxo_hash: [u8; 32],
    pub payload: IndexedPayload,
}

/// The recipient-facing payload of an [`IndexedUtxo`].
///
/// Proofless deposits are plaintext (the `emit_event` payload is public, so the
/// fields are visible without decryption); transfer/transact outputs are
/// encrypted ciphertext the recipient decrypts with their viewing key. This is
/// the `tx_viewing_pk: None` (plaintext) vs `Some(..)` (encrypted) distinction
/// the client RPC already draws.
#[derive(Clone, Debug)]
pub enum IndexedPayload {
    /// Public proofless deposit: fields are visible without decryption.
    Plaintext(ProoflessOutput),
    /// Encrypted transfer/transact output: opaque ciphertext for the recipient.
    ///
    /// Reserved for when the encrypted rail lands; nothing emits it yet.
    Encrypted(Vec<u8>),
}

/// The public fields of a proofless deposit, as carried in its plaintext event.
#[derive(Clone, Debug)]
pub struct ProoflessOutput {
    pub owner_utxo_hash: [u8; 32],
    /// Mint address; all-zero for SOL.
    pub asset: [u8; 32],
    pub amount: u64,
    /// Blinding-derivation salt (spec: Blinding derivation).
    pub salt: [u8; 16],
}

impl IndexedUtxo {
    /// The public proofless fields, or `None` if this output is encrypted.
    pub fn proofless(&self) -> Option<&ProoflessOutput> {
        match &self.payload {
            IndexedPayload::Plaintext(fields) => Some(fields),
            IndexedPayload::Encrypted(_) => None,
        }
    }
}

pub struct TestIndexer {
    tree: MerkleTree<Poseidon>,
    utxos: Vec<IndexedUtxo>,
}

impl Default for TestIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl TestIndexer {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(STATE_HEIGHT, 0),
            utxos: Vec::new(),
        }
    }

    /// Record a `ProoflessShieldEvent`: verify the emitted UTXO hash against
    /// an independent recomputation, append it to the reference tree, and
    /// remember where it landed. Returns the record.
    pub fn record_proofless_shield(
        &mut self,
        event: &ProoflessShieldEvent,
    ) -> Result<&IndexedUtxo, IndexerError> {
        let recomputed = proofless_utxo_hash(event)?;
        if recomputed != event.utxo_hash {
            return Err(IndexerError::UtxoHashMismatch {
                expected: recomputed,
                actual: event.utxo_hash,
            });
        }

        // One leaf is appended per recorded UTXO, in order, so the next leaf
        // lands at the current record count (matches the on-chain append order).
        let leaf_index = self.utxos.len() as u64;
        let record_index = self.utxos.len();
        self.tree
            .append(&event.utxo_hash)
            .map_err(|e| IndexerError::MerkleTree(format!("{e:?}")))?;
        self.utxos.push(IndexedUtxo {
            view_tag: event.view_tag,
            leaf_index,
            utxo_hash: event.utxo_hash,
            payload: IndexedPayload::Plaintext(ProoflessOutput {
                owner_utxo_hash: event.owner_utxo_hash,
                asset: event.asset,
                amount: event.amount,
                salt: event.salt,
            }),
        });
        Ok(&self.utxos[record_index])
    }

    /// Root of the reference state tree. Tests assert this equals the
    /// on-chain root (`ZolanaProgramTest::state_root`).
    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Locate a deposit the way the depositor would: by the opaque
    /// `owner_utxo_hash` they committed to. Only proofless deposits expose one;
    /// encrypted outputs hide it, so they never match.
    pub fn fetch_by_owner_utxo_hash(&self, owner_utxo_hash: &[u8; 32]) -> Option<&IndexedUtxo> {
        self.utxos.iter().find(|u| {
            u.proofless()
                .is_some_and(|p| &p.owner_utxo_hash == owner_utxo_hash)
        })
    }

    /// Locate deposits the way a recipient would: by scanning for their view
    /// tag.
    pub fn fetch_by_view_tag<'a>(
        &'a self,
        tag: &'a [u8; 32],
    ) -> impl Iterator<Item = &'a IndexedUtxo> + 'a {
        self.utxos.iter().filter(move |u| &u.view_tag == tag)
    }

    pub fn utxos(&self) -> &[IndexedUtxo] {
        &self.utxos
    }
}

/// Recompute the UTXO commitment from event fields, mirroring the program.
fn proofless_utxo_hash(event: &ProoflessShieldEvent) -> Result<[u8; 32], TransactionError> {
    let policy_data_hash = event.policy_data_hash.unwrap_or([0u8; 32]);
    let program_data_hash = event.program_data_hash.unwrap_or([0u8; 32]);
    utxo_hash(
        Address::new_from_array(event.asset),
        event.amount,
        &program_data_hash,
        &policy_data_hash,
        event.zone_program_id.map(Address::new_from_array),
        &event.owner_utxo_hash,
    )
}
