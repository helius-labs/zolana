//! Test indexer for shielded-pool events.
//!
//! Replays emitted events into an in-memory reference tree and records the
//! wallet-facing outputs that tests query.

use thiserror::Error;
use zolana_event::{proofless_output, GeneralEvent};
use zolana_hasher::Poseidon;
use zolana_interface::state::STATE_HEIGHT;
use zolana_keypair::P256Pubkey;
use zolana_merkle_tree::MerkleTree;
use zolana_transaction::{
    owner_utxo_hash, Address, OutputContext, OutputSlot, ProofInputUtxo, ShieldedTransaction,
    TransactionError,
};

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
    #[error("invalid proofless deposit payload in event")]
    InvalidProoflessPayload,
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
    /// Optional free-form memo emitted in the clear with the deposit.
    pub memo: Option<Vec<u8>>,
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
    nullifiers: Vec<[u8; 32]>,
    transactions: Vec<ShieldedTransaction>,
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
            nullifiers: Vec::new(),
            transactions: Vec::new(),
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

        let record_index = self.utxos.len();
        self.append_output_slot(
            event.leaf_index,
            event.view_tag,
            event.utxo_hash,
            IndexedPayload::Proofless(ProoflessOutput {
                owner: event.output.owner,
                asset: event.output.asset,
                amount: event.output.amount,
                blinding: event.output.blinding,
                memo: event.output.memo.clone(),
            }),
        )?;
        Ok(&self.utxos[record_index])
    }

    /// Replay a `transact` or `merge` [`GeneralEvent`]: append every output leaf,
    /// record spent nullifiers, and keep the reference tree aligned with the event.
    pub fn record_state_change(&mut self, event: &GeneralEvent) -> Result<(), IndexerError> {
        let expected_first_leaf = self.utxos.len() as u64;
        if event.first_output_leaf_index != expected_first_leaf {
            return Err(IndexerError::LeafIndexMismatch {
                expected: expected_first_leaf,
                actual: event.first_output_leaf_index,
            });
        }

        for (offset, output) in event.outputs.iter().enumerate() {
            let leaf_index = event.first_output_leaf_index + offset as u64;
            let payload = if event
                .deposit_withdraw
                .as_ref()
                .is_some_and(|deposit| deposit.is_deposit)
                && offset == 0
            {
                let proofless =
                    proofless_output(event).map_err(|_| IndexerError::InvalidProoflessPayload)?;
                IndexedPayload::Proofless(ProoflessOutput {
                    owner: proofless.owner,
                    asset: proofless.asset,
                    amount: proofless.amount,
                    blinding: proofless.blinding,
                    memo: proofless.memo.clone(),
                })
            } else {
                IndexedPayload::Encrypted(output.data.clone())
            };
            self.append_output_slot(leaf_index, output.view_tag, output.utxo_hash, payload)?;
        }

        for input in &event.inputs {
            self.nullifiers.push(input.nullifier);
        }
        Ok(())
    }

    pub fn record_transaction(
        &mut self,
        signature: solana_signature::Signature,
        event: &GeneralEvent,
        proofless: bool,
    ) {
        self.transactions
            .push(shielded_transaction_from_general_event(
                signature, event, proofless,
            ));
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn nullifiers(&self) -> &[[u8; 32]] {
        &self.nullifiers
    }

    pub fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.iter().any(|spent| spent == nullifier)
    }

    pub fn transactions(&self) -> &[ShieldedTransaction] {
        &self.transactions
    }

    /// Returns the first recorded transaction for `signature`. Today each
    /// signature emits a single `GeneralEvent`; if a transaction ever emits
    /// several, the others stay reachable via [`Self::transactions`].
    pub fn fetch_transaction_by_signature(
        &self,
        signature: &solana_signature::Signature,
    ) -> Option<&ShieldedTransaction> {
        self.transactions
            .iter()
            .find(|tx| &tx.tx_signature == signature)
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

    fn append_output_slot(
        &mut self,
        leaf_index: u64,
        view_tag: [u8; 32],
        utxo_hash: [u8; 32],
        payload: IndexedPayload,
    ) -> Result<(), IndexerError> {
        let expected_leaf = self.utxos.len() as u64;
        if leaf_index != expected_leaf {
            return Err(IndexerError::LeafIndexMismatch {
                expected: expected_leaf,
                actual: leaf_index,
            });
        }
        self.tree
            .append(&utxo_hash)
            .map_err(|e| IndexerError::MerkleTree(format!("{e:?}")))?;
        self.utxos.push(IndexedUtxo {
            view_tag,
            leaf_index,
            utxo_hash,
            payload,
        });
        Ok(())
    }
}

pub fn shielded_transaction_from_general_event(
    signature: solana_signature::Signature,
    event: &GeneralEvent,
    proofless: bool,
) -> ShieldedTransaction {
    let tx_viewing_pk = optional_tx_viewing_pk(&event.tx_viewing_pk);
    let salt = if event.salt == [0u8; 16] {
        None
    } else {
        Some(event.salt)
    };
    let output_slots = event
        .outputs
        .iter()
        .enumerate()
        .map(|(offset, output)| OutputSlot {
            view_tag: output.view_tag,
            output_context: OutputContext {
                hash: output.utxo_hash,
                tree: Address::new_from_array(event.output_tree),
                leaf_index: event.first_output_leaf_index + offset as u64,
            },
            payload: output.data.clone(),
        })
        .collect();
    let nullifiers = event.inputs.iter().map(|input| input.nullifier).collect();
    ShieldedTransaction {
        slot: 0,
        tx_signature: signature,
        tx_viewing_pk,
        salt,
        output_slots,
        nullifiers,
        proofless,
        messages: event.messages.clone(),
    }
}

fn optional_tx_viewing_pk(bytes: &[u8; 33]) -> Option<P256Pubkey> {
    if bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    P256Pubkey::from_bytes(*bytes).ok()
}

/// Recompute the UTXO commitment through the shared transaction helper.
fn proofless_utxo_hash(event: &crate::DepositOutput) -> Result<[u8; 32], TransactionError> {
    let output = &event.output;
    ProofInputUtxo::new(
        output.owner,
        &Address::new_from_array(output.asset),
        output.amount,
        &output.blinding,
    )?
    .with_data_hash(output.data_hash.unwrap_or([0u8; 32]))
    .with_zone(
        output.zone_data_hash.unwrap_or([0u8; 32]),
        &output.zone_program_id.map(Address::new_from_array),
    )?
    .hash()
}
