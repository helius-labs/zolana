use solana_address::Address;
use zolana_keypair::{
    EncryptedMergeEnvelope, MergeEnvelopeEncryption, P256Pubkey, PublicKey, ViewingKey,
};

use crate::{error::TransactionError, utxo::SppProofInputUtxo, SppProofOutputUtxo};

#[derive(Clone)]
pub struct MergeOutputEnvelope {
    pub recipient: P256Pubkey,
    pub ephemeral: ViewingKey,
}

impl MergeOutputEnvelope {
    pub fn encrypt(
        &self,
        amount: u64,
        mint: &Address,
    ) -> Result<EncryptedMergeEnvelope, TransactionError> {
        Ok(MergeEnvelopeEncryption {
            recipient: &self.recipient,
            ephemeral: &self.ephemeral,
            amount,
            mint: mint.to_bytes(),
        }
        .encrypt()?)
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

    pub fn encrypted_envelope(&self) -> Result<Option<EncryptedMergeEnvelope>, TransactionError> {
        self.envelope
            .as_ref()
            .map(|envelope| {
                envelope.encrypt(self.output_utxo.amount, &self.output_utxo.asset.asset)
            })
            .transpose()
    }
}
