use solana_address::Address;
use zolana_keypair::{MergeEnvelopeSeal, P256Pubkey, PublicKey, SealedMergeEnvelope, ViewingKey};

use crate::{error::TransactionError, utxo::SppProofInputUtxo, SppProofOutputUtxo};

#[derive(Clone)]
pub struct MergeOutputEnvelope {
    pub recipient: P256Pubkey,
    pub ephemeral: ViewingKey,
}

impl MergeOutputEnvelope {
    pub fn seal(
        &self,
        amount: u64,
        mint: &Address,
    ) -> Result<SealedMergeEnvelope, TransactionError> {
        Ok(MergeEnvelopeSeal {
            recipient: &self.recipient,
            ephemeral: &self.ephemeral,
            amount,
            mint: mint.to_bytes(),
        }
        .seal()?)
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

    pub fn sealed_envelope(&self) -> Result<Option<SealedMergeEnvelope>, TransactionError> {
        self.envelope
            .as_ref()
            .map(|envelope| envelope.seal(self.output_utxo.amount, &self.output_utxo.asset.asset))
            .transpose()
    }
}
