use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey};
use solana_pubkey::Pubkey;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::shielded::{ShieldedAddress, ShieldedKeypair};
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{NullifierKey, P256Pubkey};
use zolana_transaction::transfer::{
    RecipientOutput, TransferEncryptedUtxos, TransferSenderPlaintext,
};
use zolana_transaction::{TransactionEncryption, Utxo};

use crate::error::ClientError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256Signature {
    pub pubkey: P256Pubkey,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub owner_pubkey: Pubkey,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendWitnessRequest {
    pub utxo: Utxo,
    pub program_data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
}

impl SpendWitnessRequest {
    pub fn new(utxo: Utxo) -> Self {
        Self {
            utxo,
            program_data_hash: None,
            zone_data_hash: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedSpendWitness {
    pub nullifier_pubkey: [u8; 32],
    pub nullifier: [u8; 32],
    pub nullifier_secret: [u8; BLINDING_LEN],
}

impl ScopedSpendWitness {
    pub fn from_nullifier_key(
        request: &SpendWitnessRequest,
        nullifier_key: &NullifierKey,
    ) -> Result<Self, ClientError> {
        let program_data_hash = request.program_data_hash.unwrap_or([0u8; 32]);
        let zone_data_hash = request.zone_data_hash.unwrap_or([0u8; 32]);
        let nullifier_pubkey = nullifier_key.pubkey()?;
        let utxo_hash =
            request
                .utxo
                .hash(&nullifier_pubkey, &program_data_hash, &zone_data_hash)?;
        let nullifier = nullifier_key.nullifier(&utxo_hash, &request.utxo.blinding)?;
        Ok(Self {
            nullifier_pubkey,
            nullifier,
            nullifier_secret: *nullifier_key.secret(),
        })
    }
}

pub trait WalletAuthority {
    fn shielded_address(&self, owner_pubkey: Pubkey) -> Result<ShieldedAddress, ClientError>;

    fn derive_sender_view_tag(
        &self,
        owner_pubkey: Pubkey,
        tx_count: u64,
    ) -> Result<ViewTag, ClientError>;

    fn encrypt_transfer(
        &self,
        owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        sender: &TransferSenderPlaintext,
        recipients: &[RecipientOutput],
    ) -> Result<TransferEncryptedUtxos, ClientError>;

    fn request_user_approval(&self, _request: ApprovalRequest) -> Result<(), ClientError> {
        Ok(())
    }

    fn sign_p256(
        &self,
        owner_pubkey: Pubkey,
        message_hash: &[u8; 32],
    ) -> Result<P256Signature, ClientError>;

    fn create_spend_witness(
        &self,
        owner_pubkey: Pubkey,
        request: SpendWitnessRequest,
    ) -> Result<ScopedSpendWitness, ClientError>;
}

impl WalletAuthority for ShieldedKeypair {
    fn shielded_address(&self, _owner_pubkey: Pubkey) -> Result<ShieldedAddress, ClientError> {
        Ok(self.shielded_address()?)
    }

    fn derive_sender_view_tag(
        &self,
        _owner_pubkey: Pubkey,
        tx_count: u64,
    ) -> Result<ViewTag, ClientError> {
        Ok(self.get_sender_view_tag(tx_count)?)
    }

    fn encrypt_transfer(
        &self,
        _owner_pubkey: Pubkey,
        first_nullifier: &[u8; 32],
        sender: &TransferSenderPlaintext,
        recipients: &[RecipientOutput],
    ) -> Result<TransferEncryptedUtxos, ClientError> {
        Ok(self
            .viewing_key
            .encrypt_transfer(first_nullifier, sender, recipients)?)
    }

    fn sign_p256(
        &self,
        _owner_pubkey: Pubkey,
        message_hash: &[u8; 32],
    ) -> Result<P256Signature, ClientError> {
        let signer = EcdsaSigningKey::from_slice(self.signing_key.secret_bytes().as_slice())
            .map_err(|e| ClientError::P256Signature(e.to_string()))?;
        let signature: Signature = signer
            .sign_prehash(message_hash)
            .map_err(|e| ClientError::P256Signature(e.to_string()))?;
        let bytes = signature.to_bytes();
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&bytes[..32]);
        sig_s.copy_from_slice(&bytes[32..]);
        Ok(P256Signature {
            pubkey: self.signing_pubkey().as_p256()?,
            sig_r,
            sig_s,
        })
    }

    fn create_spend_witness(
        &self,
        _owner_pubkey: Pubkey,
        request: SpendWitnessRequest,
    ) -> Result<ScopedSpendWitness, ClientError> {
        ScopedSpendWitness::from_nullifier_key(&request, &self.nullifier_key)
    }
}
