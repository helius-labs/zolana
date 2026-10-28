use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_interface::{state::cache::CACHE_CAPACITY, ZERO_NULLIFIER_PUBKEY};
use spr_keypair::{constants::BLINDING_LEN, viewing_key::random_blinding, NullifierKey, PublicKey};

use super::{dummy_utxo_hash, Utxo};
use crate::{AddressInputError, Data, Mint, TransactionError};

/// An input UTXO with every value the transaction and the prover read from it
/// already computed, so nothing downstream holds key material. Convert from
/// [`WalletUtxo`](crate::WalletUtxo) when finalizing a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
// Serialize-only. These values are produced while finalizing a transaction and
// never decoded; a deserializer would turn a misspelled field into a dummy.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(
    feature = "tsify",
    derive(tsify::Tsify),
    tsify(large_number_types_as_bigints)
)]
pub struct SppProofInputUtxo {
    /// Reserves an address by proving non-inclusion, without spending a state leaf.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "core::ops::Not::not")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub address: bool,
    /// Includes the resolved [`Mint`], carrying both the address and compact ID.
    pub utxo: Utxo,
    /// The owner's nullifier pubkey, which the commitment folds in through
    /// `owner_hash`. Padding carries zeros: a dummy commits to no owner.
    #[cfg_attr(feature = "serde", serde(with = "spr_keypair::serde_helpers::bytes"))]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub nullifier_pubkey: [u8; 32],
    /// Commitment under [`Self::tree_id`].
    #[cfg_attr(feature = "serde", serde(with = "spr_keypair::serde_helpers::bytes"))]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub utxo_hash: [u8; 32],
    /// The nullifier the circuit derives for this slot and proves absent from
    /// the nullifier tree. Compact padding keeps its derived value here and
    /// publishes 0 instead; see [`Self::published_nullifier`].
    #[cfg_attr(feature = "serde", serde(with = "spr_keypair::serde_helpers::bytes"))]
    #[cfg_attr(feature = "tsify", tsify(type = "Uint8Array"))]
    pub nullifier: [u8; 32],
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "spr_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub data_hash: Option<[u8; 32]>,
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "spr_keypair::serde_helpers::bytes"
        )
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
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
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub cache_slot: Option<u8>,
    /// Compact padding: a dummy the instruction leaves out. It publishes
    /// nullifier 0, and SPP creates nothing for it, while the circuit still
    /// proves its derived nullifier absent from the tree.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "core::ops::Not::not")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub compact: bool,
}

impl SppProofInputUtxo {
    /// Reserve an address scoped by a signing owner, seed and tree. The seed
    /// should include the application's program id and account identifier.
    ///
    /// The slot's UTXO hash and nullifier (the address) are derived as in
    /// [`Self::validate_address`], the one derivation both sites share.
    pub fn new_address(
        owner: PublicKey,
        seed: [u8; 32],
        tree_id: u16,
    ) -> Result<Self, TransactionError> {
        let mut input = Self {
            address: true,
            utxo: Utxo {
                owner,
                asset: Mint::SOL,
                amount: 0,
                blinding: seed,
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
            utxo_hash: [0u8; 32],
            nullifier: [0u8; 32],
            data_hash: None,
            ring_data_hash: None,
            tree_id,
            leaf_index: 0,
            cache_slot: None,
            compact: false,
        };
        let (utxo_hash, nullifier) = input.derive_address()?;
        input.utxo_hash = utxo_hash;
        input.nullifier = nullifier;
        Ok(input)
    }

    /// Validate a public address-slot descriptor before building or proving it:
    /// its fields, and its UTXO hash and nullifier against the derivation.
    pub fn validate_address(&self) -> Result<(), TransactionError> {
        if !self.is_address() {
            return Err(AddressInputError::NotAnAddress.into());
        }
        if self.leaf_index != 0 {
            return Err(AddressInputError::NonZeroLeafIndex.into());
        }
        let (utxo_hash, nullifier) = self.derive_address()?;
        if utxo_hash != self.utxo_hash {
            return Err(AddressInputError::HashMismatch.into());
        }
        if nullifier != self.nullifier {
            return Err(AddressInputError::NullifierMismatch.into());
        }
        Ok(())
    }

    /// The address slot's UTXO hash and nullifier, which is the address. The
    /// nullifier key is the zero secret's and the seed is the blinding.
    fn derive_address(&self) -> Result<([u8; 32], [u8; 32]), TransactionError> {
        let utxo_hash = super::ProofInputUtxo::try_from(self)?.hash()?;
        let nullifier = NullifierKey::from_secret([0u8; BLINDING_LEN])
            .nullifier(&utxo_hash, &self.utxo.blinding)?;
        Ok((utxo_hash, nullifier))
    }

    /// The field rules of an address slot: a Solana signing owner, a
    /// canonical seed, the zero nullifier key, and nothing else.
    pub(crate) fn check_address_fields(&self) -> Result<(), TransactionError> {
        let utxo = &self.utxo;
        let fault = if self.is_dummy() {
            AddressInputError::MissingOwner
        } else if !is_canonical_bn254_scalar_be(&utxo.blinding) {
            AddressInputError::NonCanonicalSeed
        } else if self.nullifier_pubkey != ZERO_NULLIFIER_PUBKEY {
            AddressInputError::NonZeroNullifierKey
        } else if utxo.amount != 0 {
            AddressInputError::NonZeroAmount
        } else if utxo.asset != Mint::SOL {
            AddressInputError::NonZeroAsset
        } else if !utxo.data.is_empty() || self.data_hash.is_some() {
            AddressInputError::CarriesData
        } else if utxo.ring_program_id.is_some() || self.ring_data_hash.is_some() {
            AddressInputError::CarriesRing
        } else if self.is_compact() {
            AddressInputError::Compact
        } else if self.cache_slot.is_some() {
            AddressInputError::CacheSlot
        } else {
            return Ok(());
        };
        Err(fault.into())
    }

    /// This slot's entry in the private transaction hash's input chain: the
    /// commitment of a spent UTXO, 0 for padding and address slots, which spend
    /// no leaf.
    pub fn private_tx_input_hash(&self) -> [u8; 32] {
        if self.is_dummy() || self.is_address() {
            [0u8; 32]
        } else {
            self.utxo_hash
        }
    }

    /// This slot's entry in the private transaction hash's address-nullifier
    /// chain: the address of an address slot, 0 for every other slot.
    pub fn private_tx_address_nullifier(&self) -> [u8; 32] {
        if self.is_address() {
            self.nullifier
        } else {
            [0u8; 32]
        }
    }

    pub fn requires_inclusion(&self) -> bool {
        !self.is_dummy() && !self.is_address() && self.cache_slot.is_none()
    }

    pub fn is_address(&self) -> bool {
        self.address
    }

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
            address: false,
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
        if self.is_address() {
            return Err(AddressInputError::CacheSlot.into());
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
