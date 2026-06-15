//! Test indexer for shielded-pool events.
//!
//! Replays emitted events into an in-memory reference tree and records the
//! wallet-facing outputs that tests query.

use light_hasher::Poseidon;
use light_merkle_tree_reference::MerkleTree;
use thiserror::Error;
use zolana_interface::{event::ProoflessShieldEvent, state::STATE_HEIGHT};
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

/// One indexed shielded output.
#[derive(Clone, Debug)]
pub struct IndexedUtxo {
    pub view_tag: [u8; 32],
    pub leaf_index: u64,
    pub utxo_hash: [u8; 32],
    pub payload: IndexedPayload,
}

/// Recipient-facing output data.
#[derive(Clone, Debug)]
pub enum IndexedPayload {
    Plaintext(ProoflessOutput),
    Encrypted(Vec<u8>),
}

/// Public fields carried by a proofless deposit event.
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

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn fetch_by_owner_utxo_hash(&self, owner_utxo_hash: &[u8; 32]) -> Option<&IndexedUtxo> {
        self.utxos.iter().find(|u| {
            u.proofless()
                .is_some_and(|p| &p.owner_utxo_hash == owner_utxo_hash)
        })
    }

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
