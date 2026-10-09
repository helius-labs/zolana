use solana_address::Address;
use zolana_keypair::{
    EncryptedMergeEnvelope, MergeEnvelopeEncryption, P256Pubkey, PublicKey, ViewingKey,
};

use crate::{error::TransactionError, utxo::SppProofInputUtxo, SppProofOutputUtxo};

/// The default-rail merge output envelope, encrypted exactly once. The
/// ephemeral key stays next to its ciphertext because the proof needs it, and
/// keeping the fields private ties the two together.
#[derive(Clone)]
pub struct MergeOutputEnvelope {
    recipient: P256Pubkey,
    ephemeral: ViewingKey,
    encrypted: EncryptedMergeEnvelope,
}

impl MergeOutputEnvelope {
    pub fn encrypt(
        recipient: P256Pubkey,
        ephemeral: ViewingKey,
        amount: u64,
        mint: &Address,
        first_nullifier: [u8; 32],
    ) -> Result<Self, TransactionError> {
        let encrypted = MergeEnvelopeEncryption {
            recipient: &recipient,
            ephemeral: &ephemeral,
            amount,
            mint: mint.to_bytes(),
            first_nullifier,
        }
        .encrypt()?;
        Ok(Self {
            recipient,
            ephemeral,
            encrypted,
        })
    }

    pub fn recipient(&self) -> &P256Pubkey {
        &self.recipient
    }

    pub fn ephemeral(&self) -> &ViewingKey {
        &self.ephemeral
    }

    pub fn encrypted(&self) -> &EncryptedMergeEnvelope {
        &self.encrypted
    }
}

#[derive(Clone)]
pub struct MergeProofInputs {
    pub input_utxos: Vec<SppProofInputUtxo>,
    pub output_utxo: SppProofOutputUtxo,
    pub expiry_unix_ts: u64,
    pub signing_pubkey: PublicKey,
    pub output_tree_id: u16,
    pub ring_program_id: Option<Address>,
    pub envelope: Option<MergeOutputEnvelope>,
}

impl MergeProofInputs {
    pub fn output_hash(&self) -> Result<[u8; 32], TransactionError> {
        self.output_utxo.hash(self.output_tree_id)
    }

    pub fn encrypted_envelope(&self) -> Option<&EncryptedMergeEnvelope> {
        self.envelope.as_ref().map(MergeOutputEnvelope::encrypted)
    }
}
