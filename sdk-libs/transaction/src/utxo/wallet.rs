//! The indexer-side twin of [`SppProofInputUtxo`].

use solana_signature::Signature;

use super::{SppProofInputUtxo, Utxo};
use crate::{error::TransactionError, REDACTED};

/// A decrypted note with indexer context. Missing data hashes require reconstruction.
///
/// `Debug` is written by hand so a log line never prints
/// [`Self::tx_viewing_key`].
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", deny_unknown_fields)
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
    pub tx_viewing_key: Option<[u8; 32]>,
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
    /// The newest unpaused tree the indexer knew when it returned this UTXO
    /// (the `output_tree_id` of the page it came from): where a transaction
    /// that spends it appends its outputs unless the builder is told another
    /// tree. A sync stamps it with
    /// [`SpendableDecryptionResult::with_latest_tree_id`](crate::SpendableDecryptionResult::with_latest_tree_id).
    /// `None` until the indexer reports one; a transaction spending it then
    /// keeps the default output tree 0.
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

impl core::fmt::Debug for WalletUtxo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Destructured so a new field cannot be left out silently.
        let Self {
            utxo,
            nullifier_pubkey,
            utxo_hash,
            nullifier,
            tx_viewing_key,
            data_hash,
            ring_data_hash,
            tree_id,
            leaf_index,
            latest_tree_id,
            slot,
            tx_signature,
            slot_index,
        } = self;
        f.debug_struct("WalletUtxo")
            .field("utxo", utxo)
            .field("nullifier_pubkey", nullifier_pubkey)
            .field("utxo_hash", utxo_hash)
            .field("nullifier", nullifier)
            .field("tx_viewing_key", &tx_viewing_key.map(|_| REDACTED))
            .field("data_hash", data_hash)
            .field("ring_data_hash", ring_data_hash)
            .field("tree_id", tree_id)
            .field("leaf_index", leaf_index)
            .field("latest_tree_id", latest_tree_id)
            .field("slot", slot)
            .field("tx_signature", tx_signature)
            .field("slot_index", slot_index)
            .finish()
    }
}

impl WalletUtxo {
    pub fn dummy(tree_id: u16) -> Result<Self, TransactionError> {
        Ok(Self::from_dummy(SppProofInputUtxo::dummy(tree_id)?))
    }

    pub fn dummy_with_blinding(blinding: [u8; 32], tree_id: u16) -> Result<Self, TransactionError> {
        Ok(Self::from_dummy(SppProofInputUtxo::dummy_with_blinding(
            blinding, tree_id,
        )?))
    }

    fn from_dummy(dummy: SppProofInputUtxo) -> Self {
        Self {
            utxo: dummy.utxo,
            nullifier_pubkey: dummy.nullifier_pubkey,
            utxo_hash: dummy.utxo_hash,
            nullifier: dummy.nullifier,
            tx_viewing_key: None,
            data_hash: dummy.data_hash,
            ring_data_hash: dummy.ring_data_hash,
            tree_id: dummy.tree_id,
            leaf_index: dummy.leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        }
    }

    pub fn tree_id(&self) -> u16 {
        self.tree_id
    }

    /// The output tree a transaction spending `inputs` uses unless it is told
    /// another: the first real input's [`Self::latest_tree_id`], else tree 0.
    pub(crate) fn default_output_tree_id(inputs: &[Self]) -> u16 {
        inputs
            .iter()
            .find(|input| !input.utxo.owner.is_zero())
            .and_then(|input| input.latest_tree_id)
            .unwrap_or(0)
    }

    /// Whether the default-ring circuit can spend it. A ring-bound UTXO's
    /// commitment covers its ring, which that circuit does not.
    pub fn is_default_ring_spendable(&self) -> bool {
        self.utxo.ring_program_id.is_none() && self.ring_data_hash.is_none()
    }

    /// No ring binding and no attached data: the only UTXOs a split or a merge
    /// takes, since their spend input drops the committed data hashes.
    pub fn is_plain(&self) -> bool {
        self.is_default_ring_spendable() && self.data_hash.is_none() && self.utxo.data.is_empty()
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
            compact: false,
            address: false,
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
            compact: false,
            address: false,
        }
    }
}
