//! Test indexer for shielded-pool events.
//!
//! Replays emitted events into an in-memory reference tree and records the
//! wallet-facing outputs that tests query.

use thiserror::Error;
use zolana_hasher::Poseidon;
use zolana_interface::state::STATE_HEIGHT;
use zolana_merkle_tree::MerkleTree;
use zolana_transaction::{owner_utxo_hash, utxo_hash, Address, TransactionError};

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("transaction: {0}")]
    Transaction(#[from] TransactionError),
    #[error("event utxo_hash mismatch: expected {expected:?}, got {actual:?}")]
    UtxoHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("event leaf_index mismatch: expected {expected}, got {actual}")]
    LeafIndexMismatch { expected: u64, actual: u64 },
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
    Proofless(ProoflessOutput),
    Encrypted(Vec<u8>),
}

/// Public fields carried by a proofless deposit event.
#[derive(Clone, Debug)]
pub struct ProoflessOutput {
    /// Recipient `owner_hash`.
    pub owner: [u8; 32],
    /// Mint address; all-zero for SOL.
    pub asset: [u8; 32],
    pub amount: u64,
    /// Blinding sent in the clear for the recipient to spend the note.
    pub blinding: [u8; 31],
}

impl IndexedUtxo {
    pub fn proofless(&self) -> Option<&ProoflessOutput> {
        match &self.payload {
            IndexedPayload::Proofless(fields) => Some(fields),
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

    pub fn record_deposit(
        &mut self,
        event: &crate::DepositOutput,
    ) -> Result<&IndexedUtxo, IndexerError> {
        let recomputed = proofless_utxo_hash(event)?;
        if recomputed != event.utxo_hash {
            return Err(IndexerError::UtxoHashMismatch {
                expected: recomputed,
                actual: event.utxo_hash,
            });
        }

        let leaf_index = self.utxos.len() as u64;
        if event.leaf_index != leaf_index {
            return Err(IndexerError::LeafIndexMismatch {
                expected: leaf_index,
                actual: event.leaf_index,
            });
        }
        let record_index = self.utxos.len();
        self.tree
            .append(&event.utxo_hash)
            .map_err(|e| IndexerError::MerkleTree(format!("{e:?}")))?;
        self.utxos.push(IndexedUtxo {
            view_tag: event.view_tag,
            leaf_index,
            utxo_hash: event.utxo_hash,
            payload: IndexedPayload::Proofless(ProoflessOutput {
                owner: event.output.owner,
                asset: event.output.asset,
                amount: event.output.amount,
                blinding: event.output.blinding,
            }),
        });
        Ok(&self.utxos[record_index])
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn fetch_by_owner_utxo_hash(&self, target: &[u8; 32]) -> Option<&IndexedUtxo> {
        self.utxos.iter().find(|u| {
            u.proofless()
                .and_then(|p| owner_utxo_hash(&p.owner, &p.blinding).ok())
                .as_ref()
                == Some(target)
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

/// Recompute the UTXO commitment through the shared transaction helper.
fn proofless_utxo_hash(event: &crate::DepositOutput) -> Result<[u8; 32], TransactionError> {
    let output = &event.output;
    let policy_data_hash = output.policy_data_hash.unwrap_or([0u8; 32]);
    let program_data_hash = output.program_data_hash.unwrap_or([0u8; 32]);
    utxo_hash(
        Address::new_from_array(output.asset),
        output.amount,
        &program_data_hash,
        &policy_data_hash,
        output.zone_program_id.map(Address::new_from_array),
        &owner_utxo_hash(&output.owner, &output.blinding)?,
    )
}
