//! The UTXO commitment. The circuits, the shielded pool's deposits, programs
//! holding compressed state and the SDKs all hash a UTXO through
//! [`UtxoHashFields::hash`].

use spr_hasher::{Hasher, HasherError, Poseidon};

/// The field elements a UTXO hash commits to, in the circuit's order (Go
/// `circuits/spp_transaction/shared` `utxoHashGadget`). Two of them are hashes
/// of their own: `ring_hash` is `Poseidon(ring_data_hash, ring_program_id)` and
/// `owner_utxo_hash` is `Poseidon(owner_hash, blinding)`, which a ring deposit
/// receives precomputed.
pub struct UtxoHashFields<'a> {
    pub domain: &'a [u8; 32],
    /// `tree_id_field` of the tree holding the UTXO.
    pub tree_id: &'a [u8; 32],
    pub asset: &'a [u8; 32],
    pub amount: &'a [u8; 32],
    pub data_hash: &'a [u8; 32],
    pub ring_hash: &'a [u8; 32],
    pub owner_utxo_hash: &'a [u8; 32],
}

impl UtxoHashFields<'_> {
    #[inline(always)]
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            self.domain,
            self.tree_id,
            self.asset,
            self.amount,
            self.data_hash,
            self.ring_hash,
            self.owner_utxo_hash,
        ])
    }
}
