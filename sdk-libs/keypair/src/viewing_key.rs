//! P-256 viewing keypair: HPKE-style encryption of UTXO ciphertexts and
//! derivation of the view-tag secrets wallets scan for.
//!
//! Per-purpose secrets expand via labelled HKDF (`info` = `"TSPP/..."`) from
//! `view_root = ECDH(viewing_sk, P_const)`, so the secret key only needs one
//! ECDH and can stay in an HSM. View tags let a wallet locate its ciphertexts
//! at an indexer without trial decryption.

use hkdf::Hkdf;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::hash2curve::FromOkm;
use p256::{NonZeroScalar, PublicKey as P256PublicKey, Scalar, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::constants::{
    INFO_MERGE_VIEW_TAG_PREFIX, INFO_MERGE_VIEW_TAG_SECRET, INFO_PAIR_DOMAIN_PREFIX,
    INFO_PAIR_HINT_PREFIX, INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX, INFO_RECIPIENT_VIEW_TAG_SECRET,
    INFO_SENDER_VIEW_TAG_PREFIX, INFO_SENDER_VIEW_TAG_SECRET, INFO_TX_VIEWING, P_CONST_SEC1,
    SALT_LEN, VIEW_TAG_LEN,
};
use crate::encryption;
use crate::error::KeypairError;
use crate::pubkey::P256Pubkey;

pub type ViewTag = [u8; VIEW_TAG_LEN];
pub type Salt = [u8; SALT_LEN];

/// A P-256 viewing keypair.
pub struct ViewingKey {
    secret: SecretKey,
    view_root: Zeroizing<[u8; 32]>,
}

/// `view_root = HKDF-Extract(salt=∅, IKM=ECDH(viewing_sk, P_const))` — the PRK
/// all per-purpose secrets expand from.
fn view_root(secret: &SecretKey) -> Zeroizing<[u8; 32]> {
    let p_const =
        P256PublicKey::from_sec1_bytes(&P_CONST_SEC1).expect("committed P_const is valid SEC1");
    let ikm = Zeroizing::new(encryption::ecdh_x_point(secret, p_const.as_affine()));
    let (prk, _) = Hkdf::<Sha256>::extract(None, ikm.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

/// Draws a fresh per-transaction salt from the OS CSPRNG. It is folded into the
/// per-slot AEAD key derivation (not the nonce), so each `(first_nullifier,
/// salt, slot)` yields a unique single-use key. Under correct operation
/// `first_nullifier` uniqueness alone prevents key reuse; the 16-byte salt is a
/// defense-in-depth backstop against accidental `first_nullifier` reuse and must
/// stay CSPRNG-sourced to retain that property.
pub fn random_salt() -> Salt {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
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

impl ViewingKey {
    /// Generates a viewing key from the OS RNG.
    pub fn new() -> Self {
        Self::from_secret_key(SecretKey::random(&mut OsRng))
    }

    /// Wraps an existing P-256 secret key.
    pub fn from_secret_key(secret: SecretKey) -> Self {
        Self {
            view_root: view_root(&secret),
            secret,
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(Self::from_secret_key(secret))
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
    pub fn ecdh(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        encryption::ecdh_x(&self.secret, counterparty)
    }

    pub(crate) fn derive_secret32(&self, info: &[u8]) -> Result<[u8; 32], KeypairError> {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::from_prk(self.view_root.as_slice())
            .map_err(|_| KeypairError::Hkdf)?
            .expand_multi_info(&[info], &mut out)
            .map_err(|_| KeypairError::Hkdf)?;
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
    pub fn get_sender_view_tag(&self, tx_count: u64) -> Result<ViewTag, KeypairError> {
        let secret = self.sender_view_tag_secret()?;
        let mut out = ViewTag::default();
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
    ) -> Result<ViewTag, KeypairError> {
        let secret = self.recipient_view_tag_secret()?;
        let mut out = ViewTag::default();
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
    ) -> Result<ViewTag, KeypairError> {
        let secret = self.merge_view_tag_secret()?;
        let mut out = ViewTag::default();
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
    ) -> Result<ViewTag, KeypairError> {
        let shared = self.ecdh(counterparty)?;
        let mut domain = ViewTag::default();
        hkdf_expand(
            None,
            &shared,
            &[INFO_PAIR_DOMAIN_PREFIX, r_pubkey.as_bytes()],
            &mut domain,
        )?;

        let mut out = ViewTag::default();
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
