//! The indexer-side twin of [`SppProofInputUtxo`].

use solana_signature::Signature;

use super::{SppProofInputUtxo, Utxo};

/// A decrypted note with indexer context. Missing data hashes require reconstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    /// The owner's nullifier pubkey, which [`Self::utxo_hash`] folds in through
    /// `owner_hash`. Kept so converting to an input needs no address lookup.
    pub nullifier_pubkey: [u8; 32],
    /// Published commitment, checked by `verify_spendable` or transaction construction.
    pub utxo_hash: [u8; 32],
    /// The spend marker, computed while the key was in hand.
    pub nullifier: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    /// Tree ID used in commitment verification.
    pub tree_id: u16,
    /// Position of `utxo_hash` in its tree, which the inclusion proof is
    /// fetched by.
    pub leaf_index: u64,
    /// Where it was published. Ordering, history rows and re-fetch by signature
    /// read these.
    pub slot: u64,
    pub tx_signature: Signature,
    pub slot_index: u32,
}

impl WalletUtxo {
    pub fn tree_id(&self) -> u16 {
        self.tree_id
    }
}

/// A field move, never a recomputation. `utxo_hash` and `nullifier` are the
/// published values; rehashing them here would introduce a second source for
/// each and let a disagreement survive until the proof fails.
impl From<&WalletUtxo> for SppProofInputUtxo {
    fn from(spendable: &WalletUtxo) -> Self {
        Self {
            utxo: spendable.utxo.clone(),
            nullifier_pubkey: spendable.nullifier_pubkey,
            utxo_hash: spendable.utxo_hash,
            nullifier: spendable.nullifier,
            data_hash: spendable.data_hash,
            ring_data_hash: spendable.ring_data_hash,
            tree_id: spendable.tree_id,
            leaf_index: spendable.leaf_index,
            cache_slot: None,
        }
    }
}

/// The same field move, taking the UTXO rather than cloning it. Selection
/// usually owns the note it picked.
impl From<WalletUtxo> for SppProofInputUtxo {
    fn from(spendable: WalletUtxo) -> Self {
        Self {
            utxo: spendable.utxo,
            nullifier_pubkey: spendable.nullifier_pubkey,
            utxo_hash: spendable.utxo_hash,
            nullifier: spendable.nullifier,
            data_hash: spendable.data_hash,
            ring_data_hash: spendable.ring_data_hash,
            tree_id: spendable.tree_id,
            leaf_index: spendable.leaf_index,
            cache_slot: None,
        }
    }
}
