//! The indexer-side twin of [`SppProofInputUtxo`].

use solana_signature::Signature;

use super::{SppProofInputUtxo, Utxo};
use crate::error::TransactionError;

/// A decrypted note with indexer context. Missing data hashes require reconstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(
    feature = "tsify",
    derive(tsify::Tsify),
    tsify(large_number_types_as_bigints)
)]
pub struct WalletUtxo {
    pub utxo: Utxo,
    /// The owner's nullifier pubkey, which [`Self::utxo_hash`] folds in through
    /// `owner_hash`. Kept so converting to an input needs no address lookup.
    #[cfg_attr(
        feature = "serde",
        serde(with = "zolana_keypair::serde_helpers::bytes")
    )]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub nullifier_pubkey: [u8; 32],
    /// Published commitment, checked by `verify_spendable` or transaction construction.
    #[cfg_attr(
        feature = "serde",
        serde(with = "zolana_keypair::serde_helpers::bytes")
    )]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub utxo_hash: [u8; 32],
    /// The spend marker, computed while the key was in hand.
    #[cfg_attr(
        feature = "serde",
        serde(with = "zolana_keypair::serde_helpers::bytes")
    )]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub nullifier: [u8; 32],
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "zolana_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub data_hash: Option<[u8; 32]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "zolana_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub ring_data_hash: Option<[u8; 32]>,
    /// Tree ID used in commitment verification.
    pub tree_id: u16,
    /// Position of `utxo_hash` in its tree, which the inclusion proof is
    /// fetched by.
    pub leaf_index: u64,
    /// The newest tree the indexer knew when it returned this UTXO: where a
    /// transaction that spends it can append its outputs. `None` until the
    /// indexer reports it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub latest_tree_id: Option<u16>,
    /// Where it was published. Ordering, history rows and re-fetch by signature
    /// read these.
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub slot: u64,
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::serde_helpers::signature")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub tx_signature: Signature,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub slot_index: u32,
}

impl WalletUtxo {
    pub fn dummy(tree_id: u16) -> Result<Self, TransactionError> {
        let dummy = SppProofInputUtxo::dummy(tree_id)?;
        Ok(Self {
            utxo: dummy.utxo,
            nullifier_pubkey: dummy.nullifier_pubkey,
            utxo_hash: dummy.utxo_hash,
            nullifier: dummy.nullifier,
            data_hash: dummy.data_hash,
            ring_data_hash: dummy.ring_data_hash,
            tree_id: dummy.tree_id,
            leaf_index: dummy.leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        })
    }

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
