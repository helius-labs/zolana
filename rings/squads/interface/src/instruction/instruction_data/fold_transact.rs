//! `fold_transact` (tag 17) instruction data.
//!
//! A folded spend is several transfer legs of one account settled in one
//! transaction under one zone proof. Each leg keeps its own transaction and its
//! own SPP proof, so the zone forwards one `ring_transact` per leg. The fold is
//! what proves they spend the same account and pay the same recipient.

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{
    instruction::instruction_data::{transact::InputContext, EncryptedUtxos},
    types::ProofBytes,
};

/// One leg of a folded spend. The transfer half of [`TransactIxData`], minus
/// the fields a fold fixes: there is no per-leg zone proof, no public amount
/// (the shape is a transfer), and no SPL interface bump.
///
/// [`TransactIxData`]: super::TransactIxData
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct FoldTransactLeg {
    /// Compressed Groth16 SPP proof for this leg. Forwarded to SPP.
    pub spp_proof: ProofBytes,
    /// Public input this leg shares with its SPP proof.
    pub private_tx_hash: [u8; 32],
    /// Per-transaction encryption salt, forwarded verbatim into this leg's SPP
    /// instruction data.
    pub salt: [u8; 16],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_view_tags: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_utxo_hashes: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<InputContext, FixIntLen<u8>>")]
    pub input_contexts: Vec<InputContext>,
    /// Output ciphertexts for this leg, bound by the fold proof.
    pub encrypted_utxos: EncryptedUtxos,
}

/// `fold_transact` instruction data.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct FoldTransactIxData {
    /// Compressed Groth16 zone fold proof with commitment. One proof covers
    /// every leg.
    pub zone_fold_proof: ProofBytes,
    /// Unix timestamp after which the transaction is rejected. Shared, because
    /// the legs settle together or not at all.
    pub expiry: i64,
    /// Legs in the order the fold chained them. The order is part of the
    /// statement, so it must not be permuted.
    #[wincode(with = "containers::Vec<FoldTransactLeg, FixIntLen<u8>>")]
    pub legs: Vec<FoldTransactLeg>,
}

impl FoldTransactIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
