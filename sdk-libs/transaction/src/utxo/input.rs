use zolana_interface::state::cache::CACHE_CAPACITY;
use zolana_keypair::{
    constants::BLINDING_LEN, viewing_key::random_blinding, NullifierKey, PublicKey,
};

use super::{dummy_utxo_hash, Utxo};
use crate::{Data, Mint, TransactionError};

/// An input UTXO with every value the transaction and the prover read from it
/// already computed, so nothing downstream holds key material. Convert from
/// [`WalletUtxo`](crate::WalletUtxo) when finalizing a transaction.
#[derive(Clone)]
pub struct SppProofInputUtxo {
    /// Includes the resolved [`Mint`], carrying both the address and compact ID.
    pub utxo: Utxo,
    /// The owner's nullifier pubkey, which the commitment folds in through
    /// `owner_hash`. Padding carries zeros: a dummy commits to no owner.
    pub nullifier_pubkey: [u8; 32],
    /// Commitment under [`Self::tree_id`].
    pub utxo_hash: [u8; 32],
    /// The nullifier the circuit derives for this slot and proves absent from
    /// the nullifier tree. Compact padding keeps its derived value here and
    /// publishes 0 instead; see [`Self::published_nullifier`].
    pub nullifier: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    /// Raw id of the tree this UTXO is spent from. Both [`Self::utxo_hash`] and
    /// [`Self::nullifier`] fold it in, so it must match the tree the inclusion
    /// proof comes from, and a later change to it invalidates both.
    ///
    /// The indexer reports it with the slot that published the commitment, and
    /// a [`WalletUtxo`](crate::WalletUtxo) carries it from there. Where a
    /// tree account is needed, it is `pda::tree(tree_id)`.
    pub tree_id: u16,
    /// Position of the commitment in its tree. Unused for dummy inputs.
    pub leaf_index: u64,
    pub cache_slot: Option<u8>,
    /// Compact padding: a dummy the instruction leaves out. It publishes
    /// nullifier 0, and SPP creates nothing for it, while the circuit still
    /// proves its derived nullifier absent from the tree.
    pub compact: bool,
}

impl SppProofInputUtxo {
    /// Create a dummy input in the given tree with a fresh random blinding.
    pub fn dummy(tree_id: u16) -> Result<Self, TransactionError> {
        Self::dummy_with_blinding(random_blinding(), tree_id)
    }

    /// Create a dummy input with the supplied blinding and a zero nullifier key.
    pub fn dummy_with_blinding(blinding: [u8; 32], tree_id: u16) -> Result<Self, TransactionError> {
        let utxo_hash = dummy_utxo_hash(&blinding, tree_id)?;
        let nullifier =
            NullifierKey::from_secret([0u8; BLINDING_LEN]).nullifier(&utxo_hash, &blinding)?;
        Ok(Self {
            utxo: Utxo {
                owner: PublicKey::zeroed(),
                asset: Mint::SOL,
                amount: 0,
                blinding,
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_pubkey: [0u8; 32],
            utxo_hash,
            nullifier,
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index: 0,
            cache_slot: None,
            compact: false,
        })
    }

    /// Create compact padding in the given tree: a dummy over blinding 0 that
    /// publishes nullifier 0, so the instruction leaves it out and SPP creates
    /// nothing for it. The circuit still checks non-inclusion of its derived
    /// [`nullifier`](Self::nullifier), so it needs a non-inclusion witness like
    /// any dummy. It cannot fill input slot 0.
    pub fn compact(tree_id: u16) -> Result<Self, TransactionError> {
        let mut input = Self::dummy_with_blinding([0u8; 32], tree_id)?;
        input.compact = true;
        Ok(input)
    }

    pub fn with_cache_slot(mut self, slot: u8) -> Result<Self, TransactionError> {
        if usize::from(slot) >= CACHE_CAPACITY {
            return Err(TransactionError::CacheSlotOutOfRange { slot });
        }
        if self.is_dummy() {
            return Err(TransactionError::CachedDummyInput);
        }
        self.cache_slot = Some(slot);
        Ok(self)
    }

    pub fn is_dummy(&self) -> bool {
        self.utxo.owner.is_zero()
    }

    pub fn is_compact(&self) -> bool {
        self.compact
    }

    pub fn hash(&self) -> [u8; 32] {
        self.utxo_hash
    }

    pub fn nullifier(&self) -> [u8; 32] {
        self.nullifier
    }

    /// The nullifier the instruction and the public input carry for this slot:
    /// 0 for compact padding, the derived nullifier otherwise.
    pub fn published_nullifier(&self) -> [u8; 32] {
        if self.compact {
            [0u8; 32]
        } else {
            self.nullifier
        }
    }
}
