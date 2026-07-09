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

/// A human-readable description of the transaction an authority is about to
/// sign, for hosts that surface an approval step to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
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
///
/// The trait is scoped to one wallet: no method names an owner. A local
/// [`ShieldedKeypair`] is inherently scoped. A host managing many users'
/// wallets keyed by owner pubkey implements [`MultiWalletAuthority`] once and
/// scopes it per user with [`Scoped::new`], next to where it syncs that user's
/// wallet.
#[async_trait(?Send)]
pub trait WalletAuthority {
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
/// Like [`WalletAuthority`], it is scoped to one wallet.
pub trait SyncWalletAuthority {
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

/// Authority for custody hosts that manage many users' wallets keyed by the
/// owner's Solana pubkey — embedded-wallet backends, enclaves, remote signers.
///
/// Every method takes the owner explicitly. The action builders do not accept
/// this trait directly: scope it to one user with [`Scoped::new`] and pass the
/// result as the action's `authority`.
#[async_trait(?Send)]
pub trait MultiWalletAuthority {
    async fn shielded_address(&self, owner: Pubkey) -> Result<ShieldedAddress, ClientError>;

    async fn encrypt_confidential_transfer(
        &self,
        owner: Pubkey,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError>;

    async fn encrypt_anonymous_transfer(
        &self,
        owner: Pubkey,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError>;

    async fn request_user_approval(
        &self,
        _owner: Pubkey,
        _request: ApprovalRequest,
    ) -> Result<(), ClientError> {
        Ok(())
    }

    async fn sign_p256(
        &self,
        owner: Pubkey,
        message_hash: &[u8; 32],
    ) -> Result<P256Signature, ClientError>;

    async fn spend_nullifier_key(&self, owner: Pubkey) -> Result<NullifierKey, ClientError>;
}

/// A [`MultiWalletAuthority`] scoped to one user's wallet. It implements
/// [`WalletAuthority`] by passing the owner to the host on every call.
///
/// # Examples
///
/// ```no_run
/// use solana_pubkey::Pubkey;
/// use zolana_client::{
///     ClientError, CreatedTransfer, MultiWalletAuthority, PrivateTransfer, Scoped,
///     TransferRecipient, SOL_MINT,
/// };
/// use zolana_transaction::Wallet;
///
/// async fn transfer<H: MultiWalletAuthority>(
///     host: &H,
///     owner: Pubkey,
///     wallet: &Wallet,
///     destination: TransferRecipient,
///     payer: Pubkey,
/// ) -> Result<CreatedTransfer, ClientError> {
///     let authority = Scoped::new(host, owner);
///     PrivateTransfer {
///         source: wallet,
///         destination,
///         asset: SOL_MINT,
///         amount: 1_000,
///         authority: &authority,
///         payer,
///         memo: None,
///     }
///     .create()
///     .await
/// }
/// ```
pub struct Scoped<'a, H: ?Sized> {
    host: &'a H,
    owner: Pubkey,
}

impl<'a, H: ?Sized> Scoped<'a, H> {
    pub fn new(host: &'a H, owner: Pubkey) -> Self {
        Self { host, owner }
    }
}

#[async_trait(?Send)]
impl<H> WalletAuthority for Scoped<'_, H>
where
    H: MultiWalletAuthority + ?Sized,
{
    async fn shielded_address(&self) -> Result<ShieldedAddress, ClientError> {
        self.host.shielded_address(self.owner).await
    }

    async fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError> {
        self.host
            .encrypt_confidential_transfer(
                self.owner,
                first_nullifier,
                sender_tag,
                sender,
                recipients,
            )
            .await
    }

    async fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError> {
        self.host
            .encrypt_anonymous_transfer(
                self.owner,
                first_nullifier,
                sender_view_tag,
                sender,
                recipients,
            )
            .await
    }

    async fn request_user_approval(&self, request: ApprovalRequest) -> Result<(), ClientError> {
        self.host.request_user_approval(self.owner, request).await
    }

    async fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, ClientError> {
        self.host.sign_p256(self.owner, message_hash).await
    }

    async fn spend_nullifier_key(&self) -> Result<NullifierKey, ClientError> {
        self.host.spend_nullifier_key(self.owner).await
    }
}

fn recipient_slot_index(i: usize) -> Result<u32, ClientError> {
    u32::try_from(i + 1).map_err(|_| ClientError::TooManyOutputs {
        got: i + 1,
        max: u32::MAX as usize,
    })
}

impl SyncWalletAuthority for ShieldedKeypair {
    fn shielded_address(&self) -> Result<ShieldedAddress, ClientError> {
        Ok(ShieldedKeypair::shielded_address(self)?)
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_tag: ViewTag,
        sender: &TransferSenderPlaintext,
        recipients: &[ConfidentialRecipientSlot],
    ) -> Result<EncryptedTransfer, ClientError> {
        let tx = self
            .viewing_key
            .get_transaction_viewing_key(first_nullifier)?;
        let salt = random_salt();
        let self_pubkey = self.viewing_key.pubkey();

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
            .viewing_key
            .get_transaction_viewing_key(first_nullifier)?;
        let salt = random_salt();
        let self_pubkey = self.viewing_key.pubkey();

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

    fn spend_nullifier_key(&self) -> Result<NullifierKey, ClientError> {
        Ok(self.nullifier_key.clone())
    }
}
