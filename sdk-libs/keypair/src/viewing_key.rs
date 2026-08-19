//! P-256 viewing keypair: HPKE-style encryption of UTXO ciphertexts and
//! derivation of the view-tag secrets wallets scan for.
//!
//! Per-purpose secrets expand via labelled HKDF (`info` = `"TSPP/..."`) from
//! `view_root = ECDH(viewing_sk, P_const)`, so the secret key only needs one
//! ECDH and can stay in an HSM. View tags let a wallet locate its ciphertexts
//! at an indexer without trial decryption.

use std::sync::OnceLock;

use p256::{NonZeroScalar, SecretKey};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    constants::{SALT_LEN, VIEW_TAG_LEN},
    derivation::{
        self, INFO_RECIPIENT_VIEW_TAG_SECRET, INFO_SENDER_VIEW_TAG_SECRET, INFO_TX_VIEWING,
    },
    encryption,
    error::KeypairError,
    pubkey::P256Pubkey,
};

pub type ViewTag = [u8; VIEW_TAG_LEN];
pub type Salt = [u8; SALT_LEN];

/// A P-256 viewing keypair.
///
/// `view_root` costs a scalar multiplication and only the view-tag and
/// transaction-viewing secrets need it, so it resolves on first use: the
/// single-use key `get_transaction_viewing_key` returns never pays for it.
#[derive(Clone)]
pub struct ViewingKey {
    secret: SecretKey,
    view_root: OnceLock<Zeroizing<[u8; 32]>>,
}

pub fn random_salt() -> Salt {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// A fresh random blinding: a 32-byte big-endian field element with a zero top
/// byte (31 random bytes right-aligned), always below the BN254 field modulus,
/// so no rejection sampling is needed.
pub fn random_blinding() -> [u8; 32] {
    let mut blinding = [0u8; 32];
    OsRng.fill_bytes(&mut blinding[1..]);
    blinding
}

impl ViewingKey {
    /// Generates a viewing key from the OS RNG.
    pub fn new() -> Self {
        Self::from_secret_key(SecretKey::random(&mut OsRng))
    }

    /// Wraps an existing P-256 secret key.
    pub fn from_secret_key(secret: SecretKey) -> Self {
        Self {
            secret,
            view_root: OnceLock::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(Self::from_secret_key(secret))
    }

    /// HKDF-SHA256 over `ikm` with `info`, then the hash-to-scalar of the
    /// 48-byte output. Deterministic, the same inputs give the same key.
    pub fn from_hkdf(ikm: &[u8], info: &[&[u8]]) -> Result<Self, KeypairError> {
        let mut okm = Zeroizing::new([0u8; 48]);
        derivation::hkdf_expand(None, ikm, info, okm.as_mut_slice())?;
        Self::from_okm48(&okm)
    }

    pub(crate) fn from_okm48(okm: &Zeroizing<[u8; 48]>) -> Result<Self, KeypairError> {
        let scalar = derivation::scalar_from_okm(okm);
        let nonzero = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar))
            .ok_or(KeypairError::ZeroScalar)?;
        Ok(Self::from_secret_key(SecretKey::from(nonzero)))
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.secret.to_bytes());
        Zeroizing::new(out)
    }

    pub fn pubkey(&self) -> P256Pubkey {
        P256Pubkey::from_p256(&self.secret.public_key())
    }

    /// ECDH with `counterparty`, returning the shared point's x-coordinate.
    pub fn ecdh(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        if derivation::is_derivation_point(counterparty) {
            return Err(KeypairError::DerivationInput);
        }
        self.ecdh_raw(counterparty)
    }

    pub(crate) fn ecdh_raw(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        derivation::ecdh_x(&self.secret, counterparty)
    }

    fn view_root(&self) -> &Zeroizing<[u8; 32]> {
        self.view_root
            .get_or_init(|| derivation::view_root(&self.secret))
    }

    pub(crate) fn derive_secret32(&self, info: &[u8]) -> Result<[u8; 32], KeypairError> {
        let mut out = [0u8; 32];
        derivation::hkdf_expand_prk(self.view_root().as_slice(), &[info], &mut out)?;
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

    /// `tx_viewing_secret`, the seed for transaction viewing keys
    /// (`info = "TSPP/tx_viewing"`).
    pub(crate) fn tx_viewing_secret(&self) -> Result<[u8; 32], KeypairError> {
        self.derive_secret32(INFO_TX_VIEWING)
    }

    /// Sender-derived view tag for the sender's own change UTXO at `tx_count`;
    /// the sender both tags and indexes it.
    pub fn get_sender_view_tag(&self, tx_count: u64) -> Result<ViewTag, KeypairError> {
        let secret = self.sender_view_tag_secret()?;
        derivation::sender_view_tag(&secret, tx_count)
    }

    /// Recipient view tag for a `PaymentRequest` shared out-of-band.
    pub fn get_recipient_request_view_tag(
        &self,
        request_count: u64,
    ) -> Result<ViewTag, KeypairError> {
        let secret = self.recipient_view_tag_secret()?;
        derivation::recipient_request_view_tag(&secret, request_count)
    }

    fn shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        r_pubkey: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        let shared = self.ecdh(counterparty)?;
        derivation::shared_view_tag(&shared, r_pubkey, i)
    }

    /// Sender-side `recipient_shared_view_tag` for transfer `i` to a paired
    /// `counterparty` (recipient direction: `r_pubkey = counterparty`).
    pub fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.shared_view_tag(counterparty, counterparty, i)
    }

    /// Recipient-side `recipient_shared_view_tag`: scans transfers from a known
    /// `counterparty` at `i` (recipient direction: `r_pubkey = self`).
    pub fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        let r_pubkey = self.pubkey();
        self.shared_view_tag(counterparty, &r_pubkey, i)
    }

    /// Bootstrap view tag = this key's `viewing_pk` x-coordinate; anyone can
    /// derive it, so a first-time sender needs no coordination.
    pub fn recipient_bootstrap_view_tag(&self) -> ViewTag {
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
        derivation::hkdf_expand(Some(first_nullifier), &secret, &[INFO_TX_VIEWING], &mut okm)?;
        let scalar = derivation::scalar_from_okm(&okm);
        let nonzero = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar))
            .ok_or(KeypairError::ZeroScalar)?;
        Ok(ViewingKey::from_secret_key(SecretKey::from(nonzero)))
    }

    fn encrypt_utxo(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: &Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::encrypt_utxo(&self.secret, recipient_pubkey, plaintext, salt, slot_index)
    }

    /// Decrypts the UTXO ciphertext in slot `slot_index`, encrypted to this key
    /// under `tx_viewing_pubkey` with the transaction `salt`.
    pub fn decrypt_utxo(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::decrypt_utxo(
            &self.secret,
            tx_viewing_pubkey,
            ciphertext,
            &salt,
            slot_index,
        )
    }

    pub fn encrypt_slot(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.encrypt_utxo(recipient_pubkey, plaintext, &salt, slot_index)
    }

    /// Encrypts one self-contained ring-deposit plaintext to `recipient_pubkey`.
    pub fn encrypt_ring_deposit(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        salt: Salt,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::encrypt_ring_deposit(&self.secret, recipient_pubkey, plaintext, &salt)
    }

    /// Decrypts one self-contained ring-deposit ciphertext.
    pub fn decrypt_ring_deposit(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
        salt: Salt,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::decrypt_ring_deposit(&self.secret, tx_viewing_pubkey, ciphertext, &salt)
    }

    pub fn decrypt_slot_ephemeral(
        &self,
        recipient_pubkey: &P256Pubkey,
        ciphertext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::decrypt_utxo_ephemeral(
            &self.secret,
            recipient_pubkey,
            ciphertext,
            &salt,
            slot_index,
        )
    }
}

impl Default for ViewingKey {
    fn default() -> Self {
        Self::new()
    }
}
