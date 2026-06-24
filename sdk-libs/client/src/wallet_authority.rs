use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey};
use solana_pubkey::Pubkey;
use zolana_keypair::shielded::{ShieldedAddress, ShieldedKeypair};
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{NullifierKey, P256Pubkey};
use zolana_transaction::transfer::{
    RecipientOutput, TransferEncryptedUtxos, TransferSenderPlaintext,
};
use zolana_transaction::TransactionEncryption;

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

    fn spend_nullifier_key(&self, owner_pubkey: Pubkey) -> Result<NullifierKey, ClientError>;
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

    fn spend_nullifier_key(&self, _owner_pubkey: Pubkey) -> Result<NullifierKey, ClientError> {
        Ok(self.nullifier_key.clone())
    }
}
