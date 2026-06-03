//! P-256 viewing keypair: HPKE-style encryption of UTXO ciphertexts and
//! derivation of the view-tag secrets wallets scan for.
//!
//! Per-purpose secrets expand from the key via labelled HKDF (`info` =
//! `"TSPP/..."`), so the secret key can stay in an HSM. View tags let a
//! wallet locate its ciphertexts at an indexer without trial decryption.

use hkdf::Hkdf;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::hash2curve::FromOkm;
use p256::{NonZeroScalar, Scalar, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::constants::{
    BLINDING_LEN, INFO_MERGE_VIEW_TAG_PREFIX, INFO_MERGE_VIEW_TAG_SECRET, INFO_PAIR_DOMAIN_PREFIX,
    INFO_PAIR_HINT_PREFIX, INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX, INFO_RECIPIENT_VIEW_TAG_SECRET,
    INFO_SENDER_VIEW_TAG_PREFIX, INFO_SENDER_VIEW_TAG_SECRET, INFO_TX_VIEWING, P256_PUBKEY_LEN,
    PUBLIC_KEY_LEN, VIEW_TAG_LEN,
};
use crate::encryption;
use crate::error::KeypairError;
use crate::pubkey::P256Pubkey;

/// A P-256 viewing keypair.
pub struct ViewingKey {
    secret: SecretKey,
}

/// Outputs of [`ViewingKey::encrypt_transaction`]; the caller assembles
/// and serializes the transaction from these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedTransaction {
    /// Transaction viewing public key (`tx_viewing_pk`), shared by all transaction ciphertexts.
    pub tx_viewing_pubkey: P256Pubkey,
    /// Random per-transaction salt; must be passed to `decrypt_transaction`.
    pub salt: u64,
    /// Ciphertexts in input order.
    pub ciphertexts: Vec<Vec<u8>>,
}

pub(crate) fn hkdf_expand(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), KeypairError> {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand_multi_info(info, out)
        .map_err(|_| KeypairError::Hkdf)
}

const RECIPIENT_PKS_OFFSET: usize = PUBLIC_KEY_LEN + 3 * core::mem::size_of::<u64>() + BLINDING_LEN;

fn recipient_viewing_pks(
    sender_plaintext: &[u8],
    count: usize,
) -> Result<Vec<P256Pubkey>, KeypairError> {
    let expected = RECIPIENT_PKS_OFFSET + count * P256_PUBKEY_LEN;
    if sender_plaintext.len() < expected {
        return Err(KeypairError::SenderBundleTooShort {
            expected,
            actual: sender_plaintext.len(),
        });
    }
    (0..count)
        .map(|i| {
            let start = RECIPIENT_PKS_OFFSET + i * P256_PUBKEY_LEN;
            let mut pk_bytes = [0u8; P256_PUBKEY_LEN];
            pk_bytes.copy_from_slice(&sender_plaintext[start..start + P256_PUBKEY_LEN]);
            P256Pubkey::from_bytes(pk_bytes)
        })
        .collect()
}

fn slot_salt(salt: u64, index: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&salt.to_be_bytes());
    out[8..].copy_from_slice(&index.to_be_bytes());
    out
}

impl ViewingKey {
    /// Generates a viewing key from the OS RNG.
    pub fn new() -> Self {
        Self {
            secret: SecretKey::random(&mut OsRng),
        }
    }

    /// Wraps an existing P-256 secret key.
    pub fn from_secret_key(secret: SecretKey) -> Self {
        Self { secret }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(Self { secret })
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.secret.to_bytes().as_slice());
        Zeroizing::new(out)
    }

    pub fn pubkey(&self) -> P256Pubkey {
        P256Pubkey::from_p256(&self.secret.public_key())
    }

    /// ECDH with `counterparty`, returning the shared point's x-coordinate.
    pub fn ecdh(&self, counterparty: &P256Pubkey) -> [u8; 32] {
        encryption::ecdh_x(&self.secret, counterparty)
    }

    pub(crate) fn derive_secret32(&self, info: &[u8]) -> Result<[u8; 32], KeypairError> {
        let mut out = [0u8; 32];
        hkdf_expand(None, self.secret_bytes().as_slice(), &[info], &mut out)?;
        Ok(out)
    }

    /// `sender_view_tag_secret` (`info = "TSPP/sender_view_tag"`).
    pub(crate) fn sender_view_tag_secret(&self) -> Result<[u8; 32], KeypairError> {
        self.derive_secret32(INFO_SENDER_VIEW_TAG_SECRET)
    }

    /// `recipient_view_tag_secret` (`info = "TSPP/recipient_view_tag"`).
    pub(crate) fn recipient_view_tag_secret(&self) -> Result<[u8; 32], KeypairError> {
        self.derive_secret32(INFO_RECIPIENT_VIEW_TAG_SECRET)
    }

    /// `merge_view_tag_secret` (`info = "TSPP/merge_view_tag"`).
    pub(crate) fn merge_view_tag_secret(&self) -> Result<[u8; 32], KeypairError> {
        self.derive_secret32(INFO_MERGE_VIEW_TAG_SECRET)
    }

    /// `tx_viewing_secret`, the seed for transaction viewing keys
    /// (`info = "TSPP/tx_viewing"`).
    pub(crate) fn tx_viewing_secret(&self) -> Result<[u8; 32], KeypairError> {
        self.derive_secret32(INFO_TX_VIEWING)
    }

    /// Sender-derived view tag for the sender's own change UTXO at `tx_count`;
    /// the sender both tags and indexes it.
    pub fn get_sender_view_tag(&self, tx_count: u64) -> Result<[u8; VIEW_TAG_LEN], KeypairError> {
        let secret = self.sender_view_tag_secret()?;
        let mut out = [0u8; VIEW_TAG_LEN];
        hkdf_expand(
            None,
            &secret,
            &[INFO_SENDER_VIEW_TAG_PREFIX, &tx_count.to_be_bytes()],
            &mut out,
        )?;
        Ok(out)
    }

    /// Recipient view tag for a `PaymentRequest` shared out-of-band.
    pub fn get_recipient_request_view_tag(
        &self,
        request_count: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], KeypairError> {
        let secret = self.recipient_view_tag_secret()?;
        let mut out = [0u8; VIEW_TAG_LEN];
        hkdf_expand(
            None,
            &secret,
            &[
                INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX,
                &request_count.to_be_bytes(),
            ],
            &mut out,
        )?;
        Ok(out)
    }

    /// Merge view tag for the merged output at `merge_count`, namespaced by the
    /// merge service's `merge_authority_pubkey`; derived by the owner and its
    /// sync delegate, indexed by the owner.
    pub fn get_merge_view_tag(
        &self,
        merge_authority_pubkey: &[u8],
        merge_count: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], KeypairError> {
        let secret = self.merge_view_tag_secret()?;
        let mut out = [0u8; VIEW_TAG_LEN];
        hkdf_expand(
            None,
            &secret,
            &[
                INFO_MERGE_VIEW_TAG_PREFIX,
                merge_authority_pubkey,
                &merge_count.to_be_bytes(),
            ],
            &mut out,
        )?;
        Ok(out)
    }

    fn shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        r_pubkey: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], KeypairError> {
        let shared = self.ecdh(counterparty);
        let mut domain = [0u8; VIEW_TAG_LEN];
        hkdf_expand(
            None,
            &shared,
            &[INFO_PAIR_DOMAIN_PREFIX, r_pubkey.as_bytes()],
            &mut domain,
        )?;

        let mut out = [0u8; VIEW_TAG_LEN];
        hkdf_expand(
            None,
            &domain,
            &[INFO_PAIR_HINT_PREFIX, &i.to_be_bytes()],
            &mut out,
        )?;
        Ok(out)
    }

    /// Sender-side `recipient_shared_view_tag` for transfer `i` to a paired
    /// `counterparty` (recipient direction: `r_pubkey = counterparty`).
    pub fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], KeypairError> {
        self.shared_view_tag(counterparty, counterparty, i)
    }

    /// Recipient-side `recipient_shared_view_tag`: scans transfers from a known
    /// `counterparty` at `i` (recipient direction: `r_pubkey = self`).
    pub fn get_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], KeypairError> {
        let r_pubkey = self.pubkey();
        self.shared_view_tag(counterparty, &r_pubkey, i)
    }

    /// Bootstrap view tag = this key's `viewing_pk` x-coordinate; anyone can
    /// derive it, so a first-time sender needs no coordination.
    pub fn recipient_bootstrap_view_tag(&self) -> [u8; VIEW_TAG_LEN] {
        self.pubkey().x()
    }

    /// Derives the single-use transaction viewing key, salted by
    /// `first_nullifier` so it is unique per transaction. Errors with
    /// [`KeypairError::ZeroScalar`] on the negligible zero-scalar case.
    pub fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, KeypairError> {
        let secret = self.tx_viewing_secret()?;
        let mut okm = [0u8; 48];
        hkdf_expand(Some(first_nullifier), &secret, &[INFO_TX_VIEWING], &mut okm)?;
        let scalar = Scalar::from_okm(GenericArray::from_slice(&okm));
        let nonzero = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar))
            .ok_or(KeypairError::ZeroScalar)?;
        Ok(ViewingKey::from_secret_key(SecretKey::from(nonzero)))
    }

    fn encrypt_utxo(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: &[u8],
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::encrypt_utxo(&self.secret, recipient_pubkey, plaintext, salt)
    }

    /// Decrypts the UTXO ciphertext in slot `slot_index`, encrypted to this key
    /// under `tx_viewing_pubkey` with the transaction `salt`.
    pub fn decrypt_utxo(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: u64,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::decrypt_utxo(
            &self.secret,
            tx_viewing_pubkey,
            ciphertext,
            &slot_salt(salt, slot_index),
        )
    }

    /// Encrypts every plaintext of one transaction, given the sender bundle in
    /// `plaintexts[0]` and each recipient plaintext after it. Re-derives the
    /// transaction viewing key from `first_nullifier`, encrypts the sender
    /// bundle to this key, and reads each recipient's `viewing_pk` from the
    /// sender bundle's `recipient_viewing_pks` to encrypt the recipient slots.
    /// A per-transaction salt is drawn from the OS CSPRNG and combined with each
    /// slot index, so nonces stay unique across slots and across repeated builds
    /// of the same transaction. Returns an [`EncryptedTransaction`].
    pub fn encrypt_transaction(
        &self,
        first_nullifier: &[u8; 32],
        plaintexts: &[&[u8]],
    ) -> Result<EncryptedTransaction, KeypairError> {
        let (sender_plaintext, recipient_plaintexts) = plaintexts
            .split_first()
            .ok_or(KeypairError::EmptyTransaction)?;
        let recipient_pubkeys =
            recipient_viewing_pks(sender_plaintext, recipient_plaintexts.len())?;

        let salt = OsRng.next_u64();
        let tx = self.get_transaction_viewing_key(first_nullifier)?;
        let tx_viewing_pubkey = tx.pubkey();
        let mut ciphertexts = Vec::with_capacity(plaintexts.len());
        ciphertexts.push(tx.encrypt_utxo(&self.pubkey(), sender_plaintext, &slot_salt(salt, 0))?);
        for (i, (plaintext, recipient_pubkey)) in recipient_plaintexts
            .iter()
            .zip(&recipient_pubkeys)
            .enumerate()
        {
            ciphertexts.push(tx.encrypt_utxo(
                recipient_pubkey,
                plaintext,
                &slot_salt(salt, i as u32 + 1),
            )?);
        }

        Ok(EncryptedTransaction {
            tx_viewing_pubkey,
            salt,
            ciphertexts,
        })
    }

    /// Decrypts every ciphertext of one transaction, given the sender bundle in
    /// `ciphertexts[0]` and each recipient slot after it. Re-derives the transaction viewing key from
    /// `first_nullifier`, decrypts the sender bundle, and reads each recipient's
    /// `viewing_pk` from its `recipient_viewing_pks` to decrypt the recipient
    /// slots. `salt` must be the value returned by `encrypt_transaction`.
    /// Returns plaintexts in input order.
    pub fn decrypt_transaction(
        &self,
        first_nullifier: &[u8; 32],
        ciphertexts: &[&[u8]],
        salt: u64,
    ) -> Result<Vec<Vec<u8>>, KeypairError> {
        let (sender_ciphertext, recipient_ciphertexts) = ciphertexts
            .split_first()
            .ok_or(KeypairError::EmptyTransaction)?;

        let tx = self.get_transaction_viewing_key(first_nullifier)?;
        let tx_pubkey = tx.pubkey();
        let sender_plaintext = self.decrypt_utxo(sender_ciphertext, &tx_pubkey, salt, 0)?;
        let recipient_pubkeys =
            recipient_viewing_pks(&sender_plaintext, recipient_ciphertexts.len())?;

        let mut plaintexts = Vec::with_capacity(ciphertexts.len());
        plaintexts.push(sender_plaintext);
        for (i, (ciphertext, recipient_pubkey)) in recipient_ciphertexts
            .iter()
            .zip(&recipient_pubkeys)
            .enumerate()
        {
            plaintexts.push(encryption::decrypt_utxo_ephemeral(
                &tx.secret,
                recipient_pubkey,
                ciphertext,
                &slot_salt(salt, i as u32 + 1),
            )?);
        }

        Ok(plaintexts)
    }
}

impl Default for ViewingKey {
    fn default() -> Self {
        Self::new()
    }
}
