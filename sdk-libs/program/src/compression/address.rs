use zolana_hasher::{
    primitives::{is_canonical_bn254_scalar_be, right_align},
    Hasher, Poseidon,
};
use zolana_interface::ADDRESS_DOMAIN;

use super::{CompressedAccountError, PdaOwner, NO_RING_HASH};

/// The blinding of an address slot. An owner reserves one address per seed and
/// tree, so a PDA owns as many addresses as it has seeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSeed([u8; 32]);

impl AddressSeed {
    /// The owner's identity as the seed: the single address of an owner that
    /// holds one account.
    pub fn owner(owner: &PdaOwner) -> Self {
        Self(*owner.identity())
    }

    /// A program-chosen seed. It is a Poseidon input, so it must be a canonical
    /// BN254 scalar; derive it with a hash rather than truncating bytes.
    pub fn new(seed: [u8; 32]) -> Result<Self, CompressedAccountError> {
        if !is_canonical_bn254_scalar_be(&seed) {
            return Err(CompressedAccountError::NonCanonicalAddressSeed);
        }
        Ok(Self(seed))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A compressed address, created by spending an address slot: an input whose
/// UTXO carries the address domain, the owner and the seed as its blinding,
/// and zero asset, amount and data. The slot's nullifier is the address. SPP
/// inserts it into the nullifier tree of the tree the slot is spent from, so
/// the address exists once per owner, seed and tree, and never again once
/// created.
///
/// Only creation involves the address tree. After that the address is part
/// of the account's state, and the account's UTXOs may move to other trees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewAddress {
    address: [u8; 32],
    utxo_hash: [u8; 32],
    seed: AddressSeed,
    tree_id: u16,
}

impl NewAddress {
    pub fn derive(
        owner: &PdaOwner,
        seed: AddressSeed,
        tree_id: u16,
    ) -> Result<Self, CompressedAccountError> {
        let zero = [0u8; 32];
        let owner_utxo_hash = Poseidon::hashv(&[owner.owner_hash(), seed.as_bytes()])?;
        let utxo_hash = Poseidon::hashv(&[
            &right_align(&ADDRESS_DOMAIN.to_be_bytes()),
            &right_align(&tree_id.to_be_bytes()),
            &zero,
            &zero,
            &zero,
            &NO_RING_HASH,
            &owner_utxo_hash,
        ])?;
        let address = Poseidon::hashv(&[&utxo_hash, seed.as_bytes(), &zero])?;
        Ok(Self {
            address,
            utxo_hash,
            seed,
            tree_id,
        })
    }

    /// The address, which is the address slot's nullifier.
    pub fn address(&self) -> &[u8; 32] {
        &self.address
    }

    /// The address slot's UTXO hash, which a client proves in the slot.
    pub fn utxo_hash(&self) -> &[u8; 32] {
        &self.utxo_hash
    }

    pub fn seed(&self) -> &AddressSeed {
        &self.seed
    }

    /// Raw id of the tree whose nullifier tree the address enters.
    pub fn tree_id(&self) -> u16 {
        self.tree_id
    }
}
