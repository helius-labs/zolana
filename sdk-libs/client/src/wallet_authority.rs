use async_trait::async_trait;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as EcdsaSigningKey};
use solana_pubkey::Pubkey;
use zolana_interface::instruction::instruction_data::transact::OutputCiphertext;
use zolana_keypair::{
    shielded::{ShieldedAddress, ShieldedKeypair},
    viewing_key::{random_salt, Salt, ViewTag},
    NullifierKey, P256Pubkey,
};
use zolana_transaction::{
    serialization::{
        anonymous::{
            AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle,
            AnonymousSenderEncode, AnonymousTransferRecipientPlaintext,
            AnonymousTransferSenderPlaintext,
        },
        confidential::{
            ConfidentialRecipient, ConfidentialRecipientEncode, ConfidentialSenderBundle,
            ConfidentialSenderEncode, TransferRecipientPlaintext, TransferSenderPlaintext,
        },
    },
    UtxoSerialization,
};

use crate::error::ClientError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256Signature {
    pub pubkey: P256Pubkey,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub solana_pubkey: Pubkey,
    pub summary: String,
}

/// One encrypted recipient slot for a confidential transfer: its view tag, the
/// recipient viewing pubkey the ciphertext is sealed to, and the plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialRecipientSlot {
    pub view_tag: ViewTag,
    pub recipient_pubkey: P256Pubkey,
    pub plaintext: TransferRecipientPlaintext,
}

/// One encrypted recipient slot for an anonymous transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousRecipientSlot {
    pub view_tag: ViewTag,
    pub recipient_pubkey: P256Pubkey,
    pub plaintext: AnonymousTransferRecipientPlaintext,
}

/// The encrypted output slots of a transfer plus the transaction-level encryption
/// context the proof and `ExternalData` commit to. `slots[0]` is the sender
/// bundle; the rest are the real recipient ciphertexts in order. The builder pads
/// to the fixed proof shape with dummy slots.
#[derive(Clone, Debug)]
pub struct EncryptedTransfer {
    pub tx_viewing_pk: P256Pubkey,
    pub salt: Salt,
    pub slots: Vec<OutputCiphertext>,
}

/// Authority for production wallet hosts where approval, key access, or signing
/// may cross a process, device, or remote custody boundary.
#[async_trait(?Send)]
pub trait WalletAuthority {
    /// Solana owner whose user-registry record names this authority's keys.
    fn solana_pubkey(&self) -> Pubkey;

    async fn shielded_address(&self) -> Result<ShieldedAddress, ClientError>;

    async fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError>;

    async fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError>;

    async fn request_user_approval(&self, _request: ApprovalRequest) -> Result<(), ClientError> {
        Ok(())
    }

    async fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, ClientError>;

    async fn spend_nullifier_key(&self) -> Result<NullifierKey, ClientError>;
}

/// Blocking authority for tests, CLI flows, and local direct-key wallets.
pub trait SyncWalletAuthority {
    fn solana_pubkey(&self) -> Pubkey;

    fn shielded_address(&self) -> Result<ShieldedAddress, ClientError>;

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError>;

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError>;

    fn request_user_approval(&self, _request: ApprovalRequest) -> Result<(), ClientError> {
        Ok(())
    }

    fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, ClientError>;

    fn spend_nullifier_key(&self) -> Result<NullifierKey, ClientError>;
}

#[async_trait(?Send)]
impl<T> WalletAuthority for T
where
    T: SyncWalletAuthority + ?Sized,
{
    fn solana_pubkey(&self) -> Pubkey {
        SyncWalletAuthority::solana_pubkey(self)
    }

    async fn shielded_address(&self) -> Result<ShieldedAddress, ClientError> {
        SyncWalletAuthority::shielded_address(self)
    }

    async fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError> {
        SyncWalletAuthority::encrypt_confidential_transfer(
            self,
            first_nullifier,
            sender_tag,
            sender,
            recipients,
        )
    }

    async fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            self,
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    async fn request_user_approval(&self, request: ApprovalRequest) -> Result<(), ClientError> {
        SyncWalletAuthority::request_user_approval(self, request)
    }

    async fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, ClientError> {
        SyncWalletAuthority::sign_p256(self, message_hash)
    }

    async fn spend_nullifier_key(&self) -> Result<NullifierKey, ClientError> {
        SyncWalletAuthority::spend_nullifier_key(self)
    }
}

/// Owner-scoped adapter for a local shielded keypair.
///
/// A [`ShieldedKeypair`] contains shielded keys but does not know the Solana
/// account whose user-registry record publishes them. This adapter binds those
/// two pieces once, so signing cannot receive a mismatched owner separately.
pub struct LocalWalletAuthority<'a> {
    solana_pubkey: Pubkey,
    keypair: &'a ShieldedKeypair,
}

impl<'a> LocalWalletAuthority<'a> {
    pub fn new(solana_pubkey: Pubkey, keypair: &'a ShieldedKeypair) -> Self {
        Self {
            solana_pubkey,
            keypair,
        }
    }
}

fn recipient_slot_index(i: usize) -> Result<u32, ClientError> {
    u32::try_from(i + 1).map_err(|_| ClientError::TooManyOutputs {
        got: i + 1,
        max: u32::MAX as usize,
    })
}

impl SyncWalletAuthority for LocalWalletAuthority<'_> {
    fn solana_pubkey(&self) -> Pubkey {
        self.solana_pubkey
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, ClientError> {
        Ok(self.keypair.shielded_address()?)
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError> {
        let tx = self
            .keypair
            .viewing_key
            .get_transaction_viewing_key(first_nullifier)?;
        let salt = random_salt();
        let self_pubkey = self.keypair.viewing_key.pubkey();

        let mut slots = Vec::with_capacity(1 + recipients.len());
        let sender_cx = ConfidentialSenderEncode {
            tx: tx.clone(),
            self_pubkey,
            salt,
            slot_index: 0,
            blinding_seed: sender.blinding_seed,
            recipient_viewing_pks: sender.recipient_viewing_pks.clone(),
        };
        slots.push(ConfidentialSenderBundle::encode_plaintext(
            sender, sender_tag, &sender_cx,
        )?);

        for (i, recipient) in recipients.iter().enumerate() {
            let cx = ConfidentialRecipientEncode {
                tx: tx.clone(),
                recipient_pubkey: recipient.recipient_pubkey,
                salt,
                slot_index: recipient_slot_index(i)?,
            };
            slots.push(ConfidentialRecipient::encode_plaintext(
                &recipient.plaintext,
                recipient.view_tag,
                &cx,
            )?);
        }

        Ok(EncryptedTransfer {
            tx_viewing_pk: tx.pubkey(),
            salt,
            slots,
        })
    }

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError> {
        let tx = self
            .keypair
            .viewing_key
            .get_transaction_viewing_key(first_nullifier)?;
        let salt = random_salt();
        let self_pubkey = self.keypair.viewing_key.pubkey();

        let mut slots = Vec::with_capacity(1 + recipients.len());
        let sender_cx = AnonymousSenderEncode {
            tx: tx.clone(),
            self_pubkey,
            salt,
            slot_index: 0,
            blinding_seed: sender.blinding_seed,
            recipient_viewing_pks: sender.recipient_viewing_pks.clone(),
        };
        slots.push(AnonymousSenderBundle::encode_plaintext(
            sender,
            sender_view_tag,
            &sender_cx,
        )?);

        for (i, recipient) in recipients.iter().enumerate() {
            let cx = AnonymousRecipientEncode {
                tx: tx.clone(),
                recipient_pubkey: recipient.recipient_pubkey,
                sender_pubkey: recipient.plaintext.sender_pubkey,
                salt,
                slot_index: recipient_slot_index(i)?,
            };
            slots.push(AnonymousRecipient::encode_plaintext(
                &recipient.plaintext,
                recipient.view_tag,
                &cx,
            )?);
        }

        Ok(EncryptedTransfer {
            tx_viewing_pk: tx.pubkey(),
            salt,
            slots,
        })
    }

    fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, ClientError> {
        let signer =
            EcdsaSigningKey::from_slice(self.keypair.signing_key.secret_bytes().as_slice())
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
            pubkey: self.keypair.signing_pubkey().as_p256()?,
            sig_r,
            sig_s,
        })
    }

    fn spend_nullifier_key(&self) -> Result<NullifierKey, ClientError> {
        Ok(self.keypair.nullifier_key.clone())
    }
}
