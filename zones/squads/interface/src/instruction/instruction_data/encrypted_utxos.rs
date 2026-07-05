//! Zone-serialized output ciphertext blob carried in `TransactIxData`/
//! `ExecuteProposalIxData` (spec: squads `transact`, "Encrypted UTXO
//! Serialization"). Checked by the zone proof, not parsed by SPP.

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::types::{P256Pubkey, RecipientCiphertext, SenderCiphertext};

/// The output ciphertexts of a transfer or withdrawal (spec: `EncryptedUtxos`).
///
/// One ephemeral `tx_viewing_pk` is shared across all ciphertexts. The sender
/// change carries only `amount`+`asset` (its blinding is derived from
/// `tx_viewing_sk`); each recipient output carries `amount`+`asset`+`blinding`.
/// A withdrawal has no recipient output, so `recipient_ciphertexts` is empty;
/// a transfer has exactly one.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EncryptedUtxos {
    /// Ephemeral P-256 key; ECDH with the sender's and each recipient's shared
    /// viewing key.
    pub tx_viewing_pk: P256Pubkey,
    /// Sender change: `amount`+`asset`. Blinding is derived, not transmitted.
    pub sender_ciphertext: SenderCiphertext,
    /// One per recipient UTXO. Length `R` (0 for a withdrawal, 1 for a transfer).
    #[wincode(with = "containers::Vec<RecipientCiphertext, FixIntLen<u8>>")]
    pub recipient_ciphertexts: Vec<RecipientCiphertext>,
}

impl EncryptedUtxos {
    pub fn serialize(&self) -> Result<Vec<u8>, wincode::Error> {
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, wincode::Error> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
