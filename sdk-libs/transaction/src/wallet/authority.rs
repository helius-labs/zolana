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
    serialization::{
        anonymous::{
            AnonymousRecipient, AnonymousRecipientEncode, AnonymousSenderBundle,
            AnonymousSenderEncode, AnonymousTransferRecipientPlaintext,
            AnonymousTransferSenderPlaintext,
        },
        split::{Split, SplitBundlePlaintext, SplitEncode},
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

/// Per-transaction encryption envelope an authority returns: the ephemeral
/// `tx_viewing_pk` and `salt` every ciphertext in the transaction shares
/// (published in the clear), plus the sealed payload the operation produced.
#[derive(Clone, Debug)]
pub struct EncryptedEnvelope<P> {
    pub tx_viewing_pk: P256Pubkey,
    pub salt: Salt,
    pub payload: P,
}

/// Transfer payload: one ciphertext per output slot, keyed to that output's
/// owner. `None` marks a dummy slot the transfer builder pads with a
/// length-matched random ciphertext.
pub type EncryptedTransfer = EncryptedEnvelope<Vec<Option<MessageData>>>;

/// Split payload: the single sealed slot-0 `Split` bundle covering every real
/// output. Unlike a transfer there is exactly one ciphertext; all other slots
/// stay empty (covered) on the wire.
pub type EncryptedSplit = EncryptedEnvelope<MessageData>;

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

    async fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError>;

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

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError>;

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

    async fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError> {
        SyncWalletAuthority::encrypt_split(self, first_nullifier, view_tag, bundle)
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

/// Shared bodies for every local authority over a [`ShieldedKeypair`]
/// ([`LocalWalletAuthority`] and the bare keypair impl below), so the
/// encryption and signing logic exists once.
fn encrypt_confidential_transfer_with(
    keypair: &ShieldedKeypair,
    first_nullifier: &[u8; 32],
    outputs: &[SppProofOutputUtxo],
    assets: &AssetRegistry,
) -> Result<EncryptedTransfer, TransactionError> {
    let tx = keypair
        .viewing_key
        .get_transaction_viewing_key(first_nullifier)?;
    let salt = random_salt();
    let slots = encode_confidential_slots(outputs, assets, &tx, salt)?;
    Ok(EncryptedTransfer {
        tx_viewing_pk: tx.pubkey(),
        salt,
        payload: slots,
    })
}

fn encrypt_anonymous_transfer_with(
    keypair: &ShieldedKeypair,
    first_nullifier: &[u8; 32],
    sender_view_tag: ViewTag,
    sender: &AnonymousTransferSenderPlaintext,
    recipients: &[AnonymousRecipientSlot],
) -> Result<EncryptedTransfer, TransactionError> {
    let tx = keypair
        .viewing_key
        .get_transaction_viewing_key(first_nullifier)?;
    let salt = random_salt();
    let self_pubkey = keypair.viewing_key.pubkey();

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
        payload: slots,
    })
}

fn encrypt_split_with(
    keypair: &ShieldedKeypair,
    first_nullifier: &[u8; 32],
    view_tag: ViewTag,
    bundle: &SplitBundlePlaintext,
) -> Result<EncryptedSplit, TransactionError> {
    let tx = keypair
        .viewing_key
        .get_transaction_viewing_key(first_nullifier)?;
    let salt = random_salt();
    let tx_viewing_pk = tx.pubkey();
    let message = Split::encode_plaintext(
        bundle,
        view_tag,
        &SplitEncode {
            tx,
            recipient_pubkey: keypair.viewing_key.pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: bundle.blinding_seed,
        },
    )?;
    Ok(EncryptedSplit {
        tx_viewing_pk,
        salt,
        payload: message,
    })
}

fn sign_p256_with(
    keypair: &ShieldedKeypair,
    message_hash: &[u8; 32],
) -> Result<P256Signature, TransactionError> {
    let signer = EcdsaSigningKey::from_slice(keypair.signing_key.secret_bytes().as_slice())
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
        pubkey: keypair.signing_pubkey().as_p256()?,
        sig_r,
        sig_s,
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
        encrypt_confidential_transfer_with(self.keypair, first_nullifier, outputs, assets)
    }

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError> {
        encrypt_anonymous_transfer_with(
            self.keypair,
            first_nullifier,
            sender_view_tag,
            sender,
            recipients,
        )
    }

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError> {
        encrypt_split_with(self.keypair, first_nullifier, view_tag, bundle)
    }

    fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError> {
        sign_p256_with(self.keypair, message_hash)
    }

    fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        Ok(self.keypair.nullifier_key.clone())
    }
}

impl SyncWalletAuthority for ShieldedKeypair {
    fn solana_pubkey(&self) -> Address {
        ShieldedKeypair::shielded_address(self)
            .ok()
            .and_then(|address| address.solana_address().ok())
            .unwrap_or_default()
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(ShieldedKeypair::shielded_address(self)?)
    }

    fn viewing_keys(&self) -> Result<Vec<ViewingKey>, TransactionError> {
        Ok(vec![self.viewing_key.clone()])
    }

    fn encrypt_confidential_transfer(
        &self,
        first_nullifier: &[u8; 32],
        outputs: &[SppProofOutputUtxo],
        assets: &AssetRegistry,
    ) -> Result<EncryptedTransfer, TransactionError> {
        encrypt_confidential_transfer_with(self, first_nullifier, outputs, assets)
    }

    fn encrypt_anonymous_transfer(
        &self,
        first_nullifier: &[u8; 32],
        sender_view_tag: ViewTag,
        sender: &AnonymousTransferSenderPlaintext,
        recipients: &[AnonymousRecipientSlot],
    ) -> Result<EncryptedTransfer, TransactionError> {
        encrypt_anonymous_transfer_with(self, first_nullifier, sender_view_tag, sender, recipients)
    }

    fn encrypt_split(
        &self,
        first_nullifier: &[u8; 32],
        view_tag: ViewTag,
        bundle: &SplitBundlePlaintext,
    ) -> Result<EncryptedSplit, TransactionError> {
        encrypt_split_with(self, first_nullifier, view_tag, bundle)
    }

    fn sign_p256(&self, message_hash: &[u8; 32]) -> Result<P256Signature, TransactionError> {
        sign_p256_with(self, message_hash)
    }

    fn spend_nullifier_key(&self) -> Result<NullifierKey, TransactionError> {
        Ok(self.nullifier_key.clone())
    }
}
