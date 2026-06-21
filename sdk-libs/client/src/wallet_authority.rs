use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey};
use solana_pubkey::Pubkey;
use zolana_keypair::constants::{BLINDING_LEN, SALT_LEN};
use zolana_keypair::hash::owner_hash;
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
    pub inbox: Pubkey,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendWitnessRequest {
    pub utxo: Utxo,
    pub program_data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
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
    fn shielded_address(&self, inbox: Pubkey) -> Result<ShieldedAddress, ClientError>;

    fn derive_sender_view_tag(&self, inbox: Pubkey, tx_count: u64) -> Result<ViewTag, ClientError>;

    fn derive_deposit_blinding(
        &self,
        inbox: Pubkey,
        salt: &[u8; SALT_LEN],
    ) -> Result<[u8; BLINDING_LEN], ClientError>;

    fn encrypt_transfer(
        &self,
        inbox: Pubkey,
        first_nullifier: &[u8; 32],
        sender: &TransferSenderPlaintext,
        recipients: &[RecipientOutput],
    ) -> Result<TransferEncryptedUtxos, ClientError>;

    fn request_user_approval(&self, _request: ApprovalRequest) -> Result<(), ClientError> {
        Ok(())
    }

    fn sign_p256(
        &self,
        inbox: Pubkey,
        message_hash: &[u8; 32],
    ) -> Result<P256Signature, ClientError>;

    fn create_spend_witness(
        &self,
        inbox: Pubkey,
        request: SpendWitnessRequest,
    ) -> Result<ScopedSpendWitness, ClientError>;
}

impl WalletAuthority for ShieldedKeypair {
    fn shielded_address(&self, _inbox: Pubkey) -> Result<ShieldedAddress, ClientError> {
        Ok(self.shielded_address()?)
    }

    fn derive_sender_view_tag(
        &self,
        _inbox: Pubkey,
        tx_count: u64,
    ) -> Result<ViewTag, ClientError> {
        Ok(self.get_sender_view_tag(tx_count)?)
    }

    fn derive_deposit_blinding(
        &self,
        _inbox: Pubkey,
        salt: &[u8; SALT_LEN],
    ) -> Result<[u8; BLINDING_LEN], ClientError> {
        Ok(self.viewing_key.derive_proofless_blinding(salt)?)
    }

    fn encrypt_transfer(
        &self,
        _inbox: Pubkey,
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
        _inbox: Pubkey,
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
        _inbox: Pubkey,
        request: SpendWitnessRequest,
    ) -> Result<ScopedSpendWitness, ClientError> {
        ScopedSpendWitness::from_nullifier_key(&request, &self.nullifier_key)
    }
}

pub fn owner_hash_from_authority<A: WalletAuthority>(
    authority: &A,
    inbox: Pubkey,
) -> Result<[u8; 32], ClientError> {
    let address = authority.shielded_address(inbox)?;
    Ok(owner_hash(
        &address.signing_pubkey,
        &address.nullifier_pubkey,
    )?)
}
