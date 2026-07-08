//! `full_withdrawal` (tag 10) instruction data (spec: squads `full_withdrawal`).

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{
    instruction::instruction_data::{transact::InputContext, EncryptedUtxos},
    types::ProofBytes,
};

/// `full_withdrawal` instruction data (spec: squads `full_withdrawal`).
///
/// Escape-hatch public exit without the co-signer or backend. There is no zone
/// proof (the owner authorizes with a Solana signature); only the forwarded SPP
/// proof is carried. The remaining fields are what SPP's `zone_transact` needs to
/// settle the withdrawal (mirrors [`crate::instruction::TransactIxData`] minus
/// `zone_proof`, with an unsigned `public_amount`).
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct FullWithdrawalIxData {
    /// Compressed Groth16 SPP proof; forwarded to SPP.
    pub spp_proof: ProofBytes,
    /// Public withdrawn amount; negated into SPP's signed public-amount field.
    pub public_amount: u64,
    /// Binds this transaction in the SPP proof's public inputs.
    pub private_tx_hash: [u8; 32],
    /// Settlement expiry checked against the cluster clock.
    pub expiry: i64,
    /// Per-transaction encryption salt forwarded to SPP.
    pub salt: [u8; 16],
    /// One view tag for the single sender-change output slot.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_view_tags: Vec<[u8; 32]>,
    /// The single sender-change output UTXO commitment.
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub output_utxo_hashes: Vec<[u8; 32]>,
    /// Per spent input. Length `N`.
    #[wincode(with = "containers::Vec<InputContext, FixIntLen<u8>>")]
    pub input_contexts: Vec<InputContext>,
    /// Sender-change ciphertext bundle forwarded to SPP (no recipient).
    pub encrypted_utxos: EncryptedUtxos,
}

impl FullWithdrawalIxData {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
