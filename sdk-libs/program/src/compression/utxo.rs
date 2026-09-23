use zolana_hasher::{primitives::right_align, Hasher, Poseidon};
use zolana_interface::{SOL_ASSET_FIELD, UTXO_DOMAIN};

use super::{CompressedAccountError, PdaOwner};

/// `Poseidon(0, 0)`: the ring hash of a UTXO outside every ring.
pub const NO_RING_HASH: [u8; 32] = [
    0x20, 0x98, 0xf5, 0xfb, 0x9e, 0x23, 0x9e, 0xab, 0x3c, 0xea, 0xc3, 0xf2, 0x7b, 0x81, 0xe4, 0x81,
    0xdc, 0x31, 0x24, 0xd5, 0x5f, 0xfe, 0xd5, 0x23, 0xa8, 0x39, 0xee, 0x84, 0x46, 0xb6, 0x48, 0x64,
];

/// A compressed account's UTXO: owned by a program PDA, zero SOL, outside
/// every ring, and carrying the hash of the program's state.
pub struct DataUtxo<'a> {
    pub owner: &'a PdaOwner,
    /// Commits to the program's state. It must commit to a type tag and to
    /// the account's address, so that two state types, or two accounts, of one
    /// PDA cannot be confused.
    pub data_hash: [u8; 32],
    pub blinding: [u8; 32],
}

impl DataUtxo<'_> {
    /// The UTXO hash in the tree with the raw id `tree_id`. The tree id is the
    /// second Poseidon element, so a UTXO hash names the tree it lives in.
    pub fn hash(&self, tree_id: u16) -> Result<[u8; 32], CompressedAccountError> {
        if self.data_hash == [0u8; 32] {
            return Err(CompressedAccountError::ZeroDataHash);
        }
        let owner_utxo_hash = Poseidon::hashv(&[self.owner.owner_hash(), &self.blinding])?;
        Ok(Poseidon::hashv(&[
            &right_align(&UTXO_DOMAIN.to_be_bytes()),
            &right_align(&tree_id.to_be_bytes()),
            &SOL_ASSET_FIELD,
            &[0u8; 32],
            &self.data_hash,
            &NO_RING_HASH,
            &owner_utxo_hash,
        ])?)
    }

    /// The UTXO hash and the nullifier that spends it.
    pub fn key(&self, tree_id: u16) -> Result<UtxoKey, CompressedAccountError> {
        let hash = self.hash(tree_id)?;
        let nullifier = Poseidon::hashv(&[&hash, &self.blinding, &[0u8; 32]])?;
        Ok(UtxoKey { hash, nullifier })
    }
}

/// A data UTXO's hash and nullifier. Only [`DataUtxo::key`] builds one, so the
/// nullifier is always the zero-secret nullifier of that hash and blinding,
/// the one SPP inserts when a PDA owner spends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoKey {
    hash: [u8; 32],
    nullifier: [u8; 32],
}

impl UtxoKey {
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn nullifier(&self) -> &[u8; 32] {
        &self.nullifier
    }
}
