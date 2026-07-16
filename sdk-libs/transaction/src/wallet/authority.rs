use async_trait::async_trait;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as EcdsaSigningKey};
use solana_address::Address;
use zolana_event::MessageData;
use zolana_keypair::{
    shielded::{ShieldedAddress, ShieldedKeypair},
    viewing_key::{random_salt, Salt, ViewTag},
    NullifierKey, P256Pubkey, ViewingKey,
};

use crate::{
    instructions::transact::slots::encode_confidential_slots,
    serialization::anonymous::{
        AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle, AnonymousSenderEncode,
        AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext,
    },
    AssetRegistry, SppProofOutputUtxo, TransactionError, UtxoSerialization,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256Signature {
    pub pubkey: P256Pubkey,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub solana_pubkey: Address,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousRecipientSlot {
    pub view_tag: ViewTag,
    pub recipient_pubkey: P256Pubkey,
    pub plaintext: AnonymousTransferRecipientPlaintext,
}

#[derive(Clone, Debug)]
pub struct EncryptedTransfer {
    pub tx_viewing_pk: P256Pubkey,
    pub salt: Salt,
    pub slots: Vec<Option<MessageData>>,
}

/// Ephemeral key material required by a wallet scan.
///
/// Remote authorities may override `sync_material` to return one consistent
/// snapshot. Callers should keep this value inside the trusted wallet-service
/// boundary and discard it after the scan.
#[derive(Clone)]
pub struct WalletSyncMaterial {
    pub identity: ShieldedAddress,
    pub viewing_keys: Vec<ViewingKey>,
    pub nullifier_key: NullifierKey,
}

/// Owner-scoped key authority for scanning, decrypting, encrypting, and
/// authorizing one wallet. It is the sole source of key material;
/// [`crate::Wallet`] stores only public identity and indexed state and never
/// retains secrets.
#[async_trait]
pub trait WalletAuthority: Send + Sync {
    fn solana_pubkey(&self) -> Address;

    async fn shielded_address(&self) -> Result<ShieldedAddress, TransactionError>;

    /// All current and historical viewing keys needed to scan this wallet.
    async fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError>;

    async fn sync_material(&self) -> Result<WalletSyncMaterial, TransactionError> {
        Ok(WalletSyncMaterial {
            identity: self.shielded_address().await?,
            viewing_keys: self.viewing_keys().await?,
            nullifier_key: self.spend_nullifier_key().await?,
        })
    }

    async fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError>;

    async fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError>;

    async fn request_user_approval(
        &self,
        _request: ApprovalRequest,
    ) -> Result<(), TransactionError> {
        Ok(())
    }

    async fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError>;

    async fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError>;
}

/// Blocking execution form of the same authority capability, used by local
/// wallets, tests, and synchronous clients. The blanket implementation below
/// exposes every blocking authority through [`WalletAuthority`]; this is not a
/// separate least-privilege capability.
pub trait SyncWalletAuthority: Send + Sync {
    fn solana_pubkey(&self) -> Address;

    fn shielded_address(&self) -> Result<ShieldedAddress, TransactionError>;

    fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError>;

    fn sync_material(&self) -> Result<WalletSyncMaterial, TransactionError> {
        Ok(WalletSyncMaterial {
            identity: self.shielded_address()?,
            viewing_keys: self.viewing_keys()?,
            nullifier_key: self.spend_nullifier_key()?,
        })
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError>;

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError>;

    fn request_user_approval(&self, _request: ApprovalRequest) -> Result<(), TransactionError> {
        Ok(())
    }

    fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError>;

    fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError>;
}

#[async_trait]
impl<T> WalletAuthority for T
where
    T: SyncWalletAuthority + Send + Sync + ?Sized,
{
    fn solana_pubkey(&self) -> Address {
        SyncWalletAuthority::solana_pubkey(self)
    }

    async fn shielded_address(&self) -> Result<ShieldedAddress, TransactionError> {
        SyncWalletAuthority::shielded_address(self)
    }

    async fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        SyncWalletAuthority::viewing_keys(self)
    }

    async fn sync_material(&self) -> Result<WalletSyncMaterial, TransactionError> {
        SyncWalletAuthority::sync_material(self)
    }

    async fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_confidential_transfer(self, first_nullifier, outputs, assets)
    }

    async fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError> {
        SyncWalletAuthority::encrypt_anonymous_transfer(
            self,
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    async fn request_user_approval(
        &self,
        request: ApprovalRequest,
    ) -> Result<(), TransactionError> {
        SyncWalletAuthority::request_user_approval(self, request)
    }

    async fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError> {
        SyncWalletAuthority::sign_p256(self, message_hash)
    }

    async fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        SyncWalletAuthority::spend_nullifier_key(self)
    }
}

/// Binds local shielded keys to the Solana address that publishes them.
pub struct LocalWalletAuthority<'a> {
    solana_pubkey: Address,
    keypair: &'a ShieldedKeypair,
}

impl<'a> LocalWalletAuthority<'a> {
    pub fn new(solana_pubkey: impl Into<Address>, keypair: &'a ShieldedKeypair) -> Self {
        Self {
            solana_pubkey: solana_pubkey.into(),
            keypair,
        }
    }
}

fn recipient_slot_index(i: usize) -> Result<u32, TransactionError> {
    let got = i.saturating_add(1);
    u32::try_from(got).map_err(|_| TransactionError::TooManyOutputsForShape {
        got,
        max: u32::MAX as usize,
    })
}

impl SyncWalletAuthority for LocalWalletAuthority<'_> {
    fn solana_pubkey(&self) -> Address {
        self.solana_pubkey
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.keypair.shielded_address()?)
    }

    fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        Ok(vec![self.keypair.viewing_key.clone()])
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError> {
        let tx = self
            .keypair
            .viewing_key
            .get_transaction_viewing_key(first_nullifier)?;
        let salt = random_salt();
        let slots = encode_confidential_slots(outputs, assets, &tx, salt)?;
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
    ) -> Result<EncryptedTransfer, TransactionError> {
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
        slots.push(Some(AnonymousSenderBundle::encode_plaintext(
            sender,
            sender_view_tag,
            &sender_cx,
        )?));

        for (i, recipient) in recipients.iter().enumerate() {
            let cx = AnonymousRecipientEncode {
                tx: tx.clone(),
                recipient_pubkey: recipient.recipient_pubkey,
                sender_pubkey: recipient.plaintext.sender_pubkey,
                salt,
                slot_index: recipient_slot_index(i)?,
            };
            slots.push(Some(AnonymousRecipient::encode_plaintext(
                &recipient.plaintext,
                recipient.view_tag,
                &cx,
            )?));
        }

        Ok(EncryptedTransfer {
            tx_viewing_pk: tx.pubkey(),
            salt,
            slots,
        })
    }

    fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError> {
        let signer =
            EcdsaSigningKey::from_slice(self.keypair.signing_key.secret_bytes().as_slice())
                .map_err(|e| TransactionError::P256(e.to_string()))?;
        let signature: Signature = signer
            .sign_prehash(message_hash)
            .map_err(|e| TransactionError::P256(e.to_string()))?;
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

    fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        Ok(self.keypair.nullifier_key.clone())
    }
}
