//! X25519 viewing keypair: HPKE-style encryption of UTXO ciphertexts and
//! derivation of the view-tag secrets wallets scan for.
//!
//! Per-purpose secrets expand via labelled HKDF (`info` = `"TSPP/..."`) from
//! `view_root = HKDF-Extract(DST_X25519_VIEW_ROOT,
//! canonical_viewing_secret)`.
//! View tags let a wallet locate its ciphertexts at an indexer without trial
//! decryption.

use std::sync::OnceLock;

use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    constants::{SALT_LEN, VIEW_TAG_LEN},
    derivation::{
        self, INFO_RECIPIENT_VIEW_TAG_SECRET, INFO_SENDER_VIEW_TAG_SECRET, INFO_TX_VIEWING_X25519,
    },
    encryption,
    error::KeypairError,
    x25519::{X25519Keypair, X25519Pubkey},
};

pub type ViewTag = [u8; VIEW_TAG_LEN];
pub type Salt = [u8; SALT_LEN];

/// An X25519 viewing keypair.
///
/// The domain-separated role root resolves only when view tags or
/// transaction viewing keys are requested. Encryption uses the key directly.
#[derive(Clone)]
pub struct ViewingKey {
    secret: X25519Keypair,
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
        Self::from_secret_key(X25519Keypair::new())
    }

    /// Canonicalizes a viewing secret so its encrypted bytes identify one key.
    /// Generic envelope secrets retain their original RFC 7748 byte strings.
    pub fn from_secret_key(secret: X25519Keypair) -> Self {
        let mut bytes = secret.secret_bytes();
        bytes[0] &= 248;
        bytes[31] = (bytes[31] & 127) | 64;
        Self {
            secret: X25519Keypair::from_bytes(&bytes),
            view_root: OnceLock::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_secret_key(X25519Keypair::from_bytes(bytes))
    }

    /// Accepts only the unique clamped byte encoding committed by the circuit.
    /// This prevents an audit envelope from recovering an alternate secret
    /// string with the same X25519 public key.
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        if bytes[0] & 7 != 0 || bytes[31] & 0xc0 != 0x40 {
            return Err(KeypairError::InvalidSecretKey);
        }
        Ok(Self::from_bytes(bytes))
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.secret.secret_bytes()
    }

    pub fn pubkey(&self) -> X25519Pubkey {
        self.secret.pubkey()
    }

    /// ECDH with `counterparty`, rejecting noncontributory peers. The result
    /// yields every key-exchange PDA role and shared view tag for that peer,
    /// never the view root, which is salted HKDF over the raw secret.
    pub fn ecdh(&self, counterparty: &X25519Pubkey) -> Result<[u8; 32], KeypairError> {
        Ok(*self.secret.ecdh(counterparty)?)
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
        self.derive_secret32(INFO_TX_VIEWING_X25519)
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
        counterparty: &X25519Pubkey,
        r_pubkey: &X25519Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        let shared = self.ecdh(counterparty)?;
        derivation::shared_view_tag(&shared, r_pubkey, i)
    }

    /// Sender-side `recipient_shared_view_tag` for transfer `i` to a paired
    /// `counterparty` (recipient direction: `r_pubkey = counterparty`).
    pub fn get_send_shared_view_tag(
        &self,
        counterparty: &X25519Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        self.shared_view_tag(counterparty, counterparty, i)
    }

    /// Recipient-side `recipient_shared_view_tag`: scans transfers from a known
    /// `counterparty` at `i` (recipient direction: `r_pubkey = self`).
    pub fn get_recipient_shared_view_tag(
        &self,
        counterparty: &X25519Pubkey,
        i: u64,
    ) -> Result<ViewTag, KeypairError> {
        let r_pubkey = self.pubkey();
        self.shared_view_tag(counterparty, &r_pubkey, i)
    }

    /// Bootstrap view tag = this key's `viewing_pk` u-coordinate. Anyone can
    /// derive it, so a first-time sender needs no coordination.
    pub fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.pubkey().u()
    }

    /// Derives the single-use transaction viewing key, salted by
    /// `first_nullifier` so it is unique per transaction.
    pub fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, KeypairError> {
        let secret = Zeroizing::new(self.tx_viewing_secret()?);
        let mut okm = Zeroizing::new([0u8; 32]);
        derivation::hkdf_expand(
            Some(first_nullifier),
            secret.as_slice(),
            &[INFO_TX_VIEWING_X25519],
            okm.as_mut_slice(),
        )?;
        Ok(Self::from_bytes(&okm))
    }

    fn encrypt_utxo(
        &self,
        recipient_pubkey: &X25519Pubkey,
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
        tx_viewing_pubkey: &X25519Pubkey,
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
        recipient_pubkey: &X25519Pubkey,
        plaintext: &[u8],
        salt: Salt,
        slot_index: u32,
    ) -> Result<Vec<u8>, KeypairError> {
        self.encrypt_utxo(recipient_pubkey, plaintext, &salt, slot_index)
    }

    /// Encrypts one self-contained ring-deposit plaintext to `recipient_pubkey`.
    pub fn encrypt_ring_deposit(
        &self,
        recipient_pubkey: &X25519Pubkey,
        plaintext: &[u8],
        salt: Salt,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::encrypt_ring_deposit(&self.secret, recipient_pubkey, plaintext, &salt)
    }

    /// Decrypts one self-contained ring-deposit ciphertext.
    pub fn decrypt_ring_deposit(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &X25519Pubkey,
        salt: Salt,
    ) -> Result<Vec<u8>, KeypairError> {
        encryption::decrypt_ring_deposit(&self.secret, tx_viewing_pubkey, ciphertext, &salt)
    }

    pub fn decrypt_slot_ephemeral(
        &self,
        recipient_pubkey: &X25519Pubkey,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewing_secrets_are_canonical() {
        let key = ViewingKey::from_bytes(&[0; 32]);
        let secret = key.secret_bytes();
        assert_eq!(secret[0], 0);
        assert_eq!(secret[31], 64);
        assert_eq!(key.pubkey(), ViewingKey::from_bytes(&secret).pubkey());
    }

    #[test]
    fn related_peer_ecdh_cannot_recover_role_roots() {
        use crate::{derivation::PdaRoleExpansion, ShieldedPda};
        use hkdf::Hkdf;
        use sha2::Sha256;
        use solana_address::Address;

        let key = ViewingKey::from_bytes(&[7; 32]);
        assert_eq!(
            hex::encode(**key.view_root()),
            "f8f47fe6e0dee526f6e95d87ba0d52687c8729581443c14d0c928c69769cff2a"
        );
        let pda = Address::new_from_array([3; 32]);
        let owned = ShieldedPda::from_viewing_key(pda, &key).unwrap();
        // These are order-two translates of the former fixed derivation peers.
        // Clamping kills the torsion, bypassing an exact-coordinate blacklist.
        for alias in [
            "178bfe424f295736d60f0b9c30ec17044f7fba8cf9e30dcd6bb0e5ecafa7f71a",
            "99160eca742ac5b450c0c841133666ae9803b8c99cb6b69a88c5cc407e376a17",
        ] {
            let peer =
                X25519Pubkey::from_u(hex::decode(alias).unwrap().try_into().unwrap()).unwrap();
            let leaked = Zeroizing::new(key.ecdh(&peer).unwrap());
            let (candidate, _) =
                Hkdf::<Sha256>::extract(Some(derivation::DST_X25519_VIEW_ROOT), leaked.as_slice());
            assert_ne!(candidate.as_slice(), key.view_root().as_slice());
            let forged = PdaRoleExpansion::new(&leaked, pda.to_bytes());
            assert_ne!(
                forged.nullifier_key().unwrap().pubkey().unwrap(),
                owned.nullifier_pubkey().unwrap()
            );
        }
    }
}
