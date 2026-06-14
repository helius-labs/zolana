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
use light_sparse_merkle_tree::SparseMerkleTree;
use thiserror::Error;
use zolana_interface::{instruction::ProoflessShieldEvent, state::STATE_HEIGHT};
use zolana_transaction::{Address, TransactionError, Utxo};

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("transaction: {0}")]
    Transaction(#[from] TransactionError),
    #[error("event utxo_hash mismatch: expected {expected:?}, got {actual:?}")]
    UtxoHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

/// One deposited UTXO as an indexer sees it: the event fields plus its
/// position in the state tree.
#[derive(Clone, Debug)]
pub struct UtxoRecord {
    pub utxo_hash: [u8; 32],
    pub owner_utxo_hash: [u8; 32],
    /// Mint address; all-zero for SOL.
    pub asset: [u8; 32],
    pub amount: u64,
    pub view_tag: [u8; 32],
    /// Blinding-derivation salt (spec: Blinding derivation).
    pub salt: [u8; 16],
    pub leaf_index: u64,
}

pub struct PoolIndexer {
    tree: SparseMerkleTree<Poseidon, STATE_HEIGHT>,
    utxos: Vec<UtxoRecord>,
}

impl Default for PoolIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolIndexer {
    pub fn new() -> Self {
        Self {
            tree: SparseMerkleTree::new_empty(),
            utxos: Vec::new(),
        }
    }

    /// Record a `ProoflessShieldEvent`: verify the emitted UTXO hash against
    /// an independent recomputation, append it to the reference tree, and
    /// remember where it landed. Returns the record.
    pub fn record_proofless_shield(
        &mut self,
        event: &ProoflessShieldEvent,
    ) -> Result<&UtxoRecord, IndexerError> {
        let recomputed = proofless_utxo_hash(event)?;
        if recomputed != event.utxo_hash {
            return Err(IndexerError::UtxoHashMismatch {
                expected: recomputed,
                actual: event.utxo_hash,
            });
        }

        let leaf_index = self.tree.get_next_index() as u64;
        let record_index = self.utxos.len();
        self.tree.append(event.utxo_hash);
        self.utxos.push(UtxoRecord {
            utxo_hash: event.utxo_hash,
            owner_utxo_hash: event.owner_utxo_hash,
            asset: event.asset,
            amount: event.amount,
            view_tag: event.view_tag,
            salt: event.salt,
            leaf_index,
        });
        Ok(&self.utxos[record_index])
    }

    /// Root of the reference state tree. Tests assert this equals the
    /// on-chain root (`PoolTestRig::state_root`).
    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Locate a deposit the way the depositor would: by the opaque
    /// `owner_utxo_hash` they committed to.
    pub fn fetch_by_owner_utxo_hash(&self, owner_utxo_hash: &[u8; 32]) -> Option<&UtxoRecord> {
        self.utxos
            .iter()
            .find(|u| &u.owner_utxo_hash == owner_utxo_hash)
    }

    /// Locate deposits the way a recipient would: by scanning for their view
    /// tag.
    pub fn fetch_by_view_tag<'a>(
        &'a self,
        tag: &'a [u8; 32],
    ) -> impl Iterator<Item = &'a UtxoRecord> + 'a {
        self.utxos.iter().filter(move |u| &u.view_tag == tag)
    }

    pub fn utxos(&self) -> &[UtxoRecord] {
        &self.utxos
    }
}

/// Recompute the UTXO commitment from event fields, mirroring the program.
fn proofless_utxo_hash(event: &ProoflessShieldEvent) -> Result<[u8; 32], TransactionError> {
    let policy_data_hash = event.policy_data_hash.unwrap_or([0u8; 32]);
    let program_data_hash = event.program_data_hash.unwrap_or([0u8; 32]);
    Utxo::commitment_from_owner_utxo_hash(
        Address::new_from_array(event.asset),
        event.amount,
        &program_data_hash,
        &policy_data_hash,
        event.zone_program_id.map(Address::new_from_array),
        &event.owner_utxo_hash,
    )
}
