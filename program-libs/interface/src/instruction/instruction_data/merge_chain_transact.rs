use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use super::merge_transact::{MergeProof, MergeProofRef, RefConfig};
use crate::verifying_keys::{
    merge_chain::{merge_chain_legs, merge_chain_tree_inputs},
    Bsb22Commitment,
};

/// `merge_chain_transact` instruction data (spec: SPP `merge_chain_transact`).
///
/// A chain collapses more UTXOs than the merge circuit's fixed eight by feeding
/// an intermediate output straight into the next level. Only the top output is
/// inserted, so the wire carries one output hash against `levels`-many legs.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeChainTransactIxData {
    pub expiry_unix_ts: u64,
    pub proof: MergeProof,
    /// Always present. Emulated arithmetic in the recursive verifier
    /// range-checks its limbs, which produces the commitment.
    pub bsb22_commitment: Bsb22Commitment,
    pub output_utxo_hash: [u8; 32],
    /// When true the owner identity (`pk_field(user_signing_pk)`) is derived from
    /// the registry account's ed25519 `owner` instead of its P256 `owner_p256`.
    pub eddsa_owner: bool,
    /// Legs per level, bottom level first. Selects the outer verifying key, so
    /// a chain cannot claim a tree its proof did not collapse.
    #[wincode(with = "containers::Vec<u8, FixIntLen<u8>>")]
    pub levels: Vec<u8>,
    /// One per leg, in leg order. Intermediate legs publish nothing else, so
    /// this is what an indexer reconstructs them from.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub private_tx_hashes: Vec<[u8; 32]>,
    /// Tree-backed slots only, in leg then slot order. A chained slot spends a
    /// UTXO no tree holds, so it has no nullifier to insert.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub utxo_tree_root_index: Vec<u16>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub nullifier_tree_root_index: Vec<u16>,
}

impl MergeChainTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(data)?)
    }
}

/// Zero-copy view of [`MergeChainTransactIxData`]. The proof points alias the
/// instruction buffer. Only the small element vectors are read owned.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead)]
pub struct MergeChainTransactIxDataRef<'a> {
    pub expiry_unix_ts: u64,
    pub proof: MergeProofRef<'a>,
    pub bsb22_commitment: Bsb22Commitment,
    pub output_utxo_hash: &'a [u8; 32],
    pub eddsa_owner: bool,
    #[wincode(with = "containers::Vec<u8, FixIntLen<u8>>")]
    pub levels: Vec<u8>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub private_tx_hashes: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub nullifiers: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub utxo_tree_root_index: Vec<u16>,
    #[wincode(with = "containers::Vec<u16, FixIntLen<u8>>")]
    pub nullifier_tree_root_index: Vec<u16>,
}

impl<'a> MergeChainTransactIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, wincode::ReadError> {
        let parsed: Self = wincode::config::deserialize_exact(data, RefConfig::new())?;
        parsed.validate_shape()?;
        Ok(parsed)
    }

    /// Legs the level shape names. Only valid after `validate_shape`.
    pub fn legs(&self) -> usize {
        self.private_tx_hashes.len()
    }

    /// Enforce that every vector matches the level shape. The shape is
    /// attacker-controlled and selects the verifying key, so it is resolved
    /// before any length is trusted.
    fn validate_shape(&self) -> Result<(), wincode::ReadError> {
        const INVALID: wincode::ReadError = wincode::ReadError::Custom("invalid merge chain shape");
        let legs = merge_chain_legs(&self.levels).ok_or(INVALID)?;
        let tree_inputs = merge_chain_tree_inputs(legs);
        if self.private_tx_hashes.len() != legs
            || self.nullifiers.len() != tree_inputs
            || self.utxo_tree_root_index.len() != tree_inputs
            || self.nullifier_tree_root_index.len() != tree_inputs
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(levels: &[u8]) -> MergeChainTransactIxData {
        let legs = merge_chain_legs(levels).expect("closed tree");
        let tree_inputs = merge_chain_tree_inputs(legs);
        MergeChainTransactIxData {
            expiry_unix_ts: 42,
            proof: MergeProof::zeroed(),
            bsb22_commitment: Bsb22Commitment {
                commitment: [1u8; 32],
                commitment_pok: [2u8; 32],
            },
            output_utxo_hash: [9u8; 32],
            eddsa_owner: false,
            levels: levels.to_vec(),
            private_tx_hashes: (0..legs as u8).map(|i| [i; 32]).collect(),
            nullifiers: (0..tree_inputs as u8).map(|i| [i; 32]).collect(),
            utxo_tree_root_index: (0..tree_inputs as u16).collect(),
            nullifier_tree_root_index: (0..tree_inputs as u16).collect(),
        }
    }

    #[test]
    fn two_leg_chain_fits_a_legacy_transaction() {
        let bytes = data(&[1, 1]).serialize().expect("serialize");
        let view = MergeChainTransactIxDataRef::from_bytes(&bytes).expect("parse");
        assert_eq!(view.legs(), 2);
        assert_eq!(view.nullifiers.len(), 15);
        // expiry(8) || proof(128) || commitment(64) || output_hash(32) ||
        // eddsa_owner(1) plus five u8-prefixed vectors. Under 1232 once the
        // account list is added.
        assert_eq!(bytes.len(), 844);
    }

    #[test]
    fn three_leg_chain_needs_the_larger_transaction() {
        let bytes = data(&[2, 1]).serialize().expect("serialize");
        let view = MergeChainTransactIxDataRef::from_bytes(&bytes).expect("parse");
        assert_eq!(view.legs(), 3);
        assert_eq!(view.nullifiers.len(), 22);
        assert_eq!(bytes.len(), 1128);
    }

    #[test]
    fn rejects_a_tree_that_does_not_close() {
        for levels in [
            vec![],
            vec![4],
            vec![4, 2],
            vec![4, 0, 1],
            vec![9, 1],
            vec![2, 2],
        ] {
            assert!(merge_chain_legs(&levels).is_none(), "levels {levels:?}");
        }
    }

    /// One logical instruction must have one byte encoding. Trailing bytes are
    /// unconstrained payload the proof never covers.
    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = data(&[1, 1]).serialize().expect("serialize");
        bytes.push(0);
        assert!(MergeChainTransactIxDataRef::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_vectors_that_disagree_with_the_shape() {
        let mut owned = data(&[1, 1]);
        owned.nullifiers.pop();
        let bytes = owned.serialize().expect("serialize");
        assert!(MergeChainTransactIxDataRef::from_bytes(&bytes).is_err());

        let mut owned = data(&[1, 1]);
        owned.private_tx_hashes.pop();
        let bytes = owned.serialize().expect("serialize");
        assert!(MergeChainTransactIxDataRef::from_bytes(&bytes).is_err());
    }
}
