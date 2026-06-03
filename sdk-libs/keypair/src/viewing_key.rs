use hkdf::Hkdf;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::hash2curve::FromOkm;
use p256::{NonZeroScalar, Scalar, SecretKey};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::constants::{
    INFO_MERGE_VIEW_TAG_PREFIX, INFO_MERGE_VIEW_TAG_SECRET, INFO_PAIR_DOMAIN_PREFIX,
    INFO_PAIR_HINT_PREFIX, INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX, INFO_RECIPIENT_VIEW_TAG_SECRET,
    INFO_SENDER_VIEW_TAG_PREFIX, INFO_SENDER_VIEW_TAG_SECRET, INFO_TX_VIEWING, VIEW_TAG_LEN,
};
use crate::encryption;
use crate::error::Error;
use crate::pubkey::P256Pubkey;

pub struct ViewingKey {
    secret: SecretKey,
}

pub(crate) fn hkdf_expand(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand_multi_info(info, out)
        .map_err(|_| Error::Hkdf)
}

impl ViewingKey {
    pub fn new() -> Self {
        Self {
            secret: SecretKey::random(&mut OsRng),
        }
    }

    pub fn from_sk(secret: SecretKey) -> Self {
        Self { secret }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| Error::InvalidSecretKey)?;
        Ok(Self { secret })
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.secret.to_bytes().as_slice());
        Zeroizing::new(out)
    }

    pub fn viewing_pubkey(&self) -> P256Pubkey {
        P256Pubkey::from_p256(&self.secret.public_key())
    }

    pub fn ecdh(&self, counterparty: &P256Pubkey) -> [u8; 32] {
        encryption::ecdh_x(&self.secret, counterparty)
    }

    pub(crate) fn derive_secret32(&self, info: &[u8]) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        hkdf_expand(None, self.secret_bytes().as_slice(), &[info], &mut out)?;
        Ok(out)
    }

    pub fn sender_view_tag_secret(&self) -> Result<[u8; 32], Error> {
        self.derive_secret32(INFO_SENDER_VIEW_TAG_SECRET)
    }

    pub fn recipient_view_tag_secret(&self) -> Result<[u8; 32], Error> {
        self.derive_secret32(INFO_RECIPIENT_VIEW_TAG_SECRET)
    }

    pub fn merge_view_tag_secret(&self) -> Result<[u8; 32], Error> {
        self.derive_secret32(INFO_MERGE_VIEW_TAG_SECRET)
    }

    pub fn tx_viewing_secret(&self) -> Result<[u8; 32], Error> {
        self.derive_secret32(INFO_TX_VIEWING)
    }

    pub fn get_sender_view_tag(&self, tx_count: u64) -> Result<[u8; VIEW_TAG_LEN], Error> {
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

    pub fn get_recipient_request_view_tag(
        &self,
        request_count: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], Error> {
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

    pub fn get_merge_view_tag(
        &self,
        merge_authority_pubkey: &[u8],
        merge_count: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], Error> {
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
    ) -> Result<[u8; VIEW_TAG_LEN], Error> {
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

    pub fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], Error> {
        self.shared_view_tag(counterparty, counterparty, i)
    }

    pub fn get_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        i: u64,
    ) -> Result<[u8; VIEW_TAG_LEN], Error> {
        let r_pubkey = self.viewing_pubkey();
        self.shared_view_tag(counterparty, &r_pubkey, i)
    }

    pub fn recipient_bootstrap_view_tag(&self) -> [u8; VIEW_TAG_LEN] {
        self.viewing_pubkey().x()
    }

    pub fn get_transaction_viewing_key(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<ViewingKey, Error> {
        let secret = self.tx_viewing_secret()?;
        let mut okm = [0u8; 48];
        hkdf_expand(Some(first_nullifier), &secret, &[INFO_TX_VIEWING], &mut okm)?;
        let scalar = Scalar::from_okm(GenericArray::from_slice(&okm));
        let nonzero = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar))
            .ok_or(Error::InvalidSecretKey)?;
        Ok(ViewingKey::from_sk(SecretKey::from(nonzero)))
    }

    pub fn encrypt(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        encryption::encrypt_transfer(&self.secret, recipient_pubkey, plaintext)
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        tx_viewing_pubkey: &P256Pubkey,
    ) -> Result<Vec<u8>, Error> {
        encryption::decrypt_transfer(&self.secret, tx_viewing_pubkey, ciphertext)
    }

    pub fn encrypt_with(
        &self,
        recipient_pubkey: &P256Pubkey,
        plaintext: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        encryption::encrypt(&self.secret, recipient_pubkey, plaintext, info, aad)
    }

    pub fn decrypt_with(
        &self,
        ciphertext: &[u8],
        ephemeral_pubkey: &P256Pubkey,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        encryption::decrypt(&self.secret, ephemeral_pubkey, ciphertext, info, aad)
    }
}

impl Default for ViewingKey {
    fn default() -> Self {
        Self::new()
    }
}
