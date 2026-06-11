use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::GlobalSharedViewKeyError;

const PUBKEY_LEN: usize = 65;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const ECIES_INFO: &[u8] = b"global-shared-viewkey/ecies/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EciesCiphertext {
    pub eph_pubkey: [u8; PUBKEY_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl EciesCiphertext {
    pub fn encrypt(
        recipient: &PublicKey,
        plaintext: &[u8],
    ) -> Result<Self, GlobalSharedViewKeyError> {
        let ephemeral = SecretKey::random(&mut OsRng);
        let eph_pubkey = encode_point(&ephemeral.public_key());
        let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
        let key = derive_key(
            shared.raw_secret_bytes().as_slice(),
            &eph_pubkey,
            &encode_point(recipient),
        )?;

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| GlobalSharedViewKeyError::Crypto("aes key"))?
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| GlobalSharedViewKeyError::Crypto("aes-gcm encrypt"))?;

        Ok(Self {
            eph_pubkey,
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt(
        &self,
        recipient: &SecretKey,
    ) -> Result<Zeroizing<Vec<u8>>, GlobalSharedViewKeyError> {
        let eph_pubkey = PublicKey::from_sec1_bytes(&self.eph_pubkey)
            .map_err(|_| GlobalSharedViewKeyError::Crypto("ephemeral pubkey"))?;
        let shared = diffie_hellman(recipient.to_nonzero_scalar(), eph_pubkey.as_affine());
        let key = derive_key(
            shared.raw_secret_bytes().as_slice(),
            &self.eph_pubkey,
            &encode_point(&recipient.public_key()),
        )?;

        let plaintext = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| GlobalSharedViewKeyError::Crypto("aes key"))?
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_slice())
            .map_err(|_| GlobalSharedViewKeyError::Crypto("aes-gcm decrypt"))?;
        Ok(Zeroizing::new(plaintext))
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(PUBKEY_LEN + NONCE_LEN + self.ciphertext.len());
        message.extend_from_slice(&self.eph_pubkey);
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&self.ciphertext);
        message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKeyShare {
    pub encrypted: EciesCiphertext,
    pub signature: [u8; 64],
}

impl EncryptedKeyShare {
    pub fn encrypt(
        authority_pubkey: &PublicKey,
        signing_key: &SigningKey,
        share: &[u8],
    ) -> Result<Self, GlobalSharedViewKeyError> {
        let encrypted = EciesCiphertext::encrypt(authority_pubkey, share)?;
        let signature: Signature = signing_key.sign(&encrypted.signed_bytes());
        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(signature.to_bytes().as_slice());
        Ok(Self {
            encrypted,
            signature: signature_bytes,
        })
    }

    pub fn decrypt(
        &self,
        authority_key: &SecretKey,
        verifying_key: &VerifyingKey,
    ) -> Result<Zeroizing<Vec<u8>>, GlobalSharedViewKeyError> {
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| GlobalSharedViewKeyError::BadSignature)?;
        verifying_key
            .verify(&self.encrypted.signed_bytes(), &signature)
            .map_err(|_| GlobalSharedViewKeyError::BadSignature)?;
        self.encrypted.decrypt(authority_key)
    }
}

fn encode_point(pk: &PublicKey) -> [u8; PUBKEY_LEN] {
    let encoded = pk.to_encoded_point(false);
    let mut out = [0u8; PUBKEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn derive_key(
    shared: &[u8],
    eph_pubkey: &[u8; PUBKEY_LEN],
    recipient_pubkey: &[u8; PUBKEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, GlobalSharedViewKeyError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand_multi_info(
        &[ECIES_INFO, eph_pubkey, recipient_pubkey],
        key.as_mut_slice(),
    )
    .map_err(|_| GlobalSharedViewKeyError::Crypto("hkdf"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_recovers_share() {
        let authority = SecretKey::random(&mut OsRng);
        let signing = SigningKey::random(&mut OsRng);
        let verifying = VerifyingKey::from(&signing);
        let share = [9u8; 33];

        let encrypted =
            EncryptedKeyShare::encrypt(&authority.public_key(), &signing, &share).expect("encrypt");
        let decrypted = encrypted.decrypt(&authority, &verifying).expect("decrypt");

        assert_eq!(decrypted.as_slice(), share.as_slice());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let authority = SecretKey::random(&mut OsRng);
        let signing = SigningKey::random(&mut OsRng);
        let verifying = VerifyingKey::from(&signing);
        let share = [9u8; 33];

        let mut encrypted =
            EncryptedKeyShare::encrypt(&authority.public_key(), &signing, &share).expect("encrypt");
        encrypted.signature = [0u8; 64];

        assert_eq!(
            encrypted.decrypt(&authority, &verifying),
            Err(GlobalSharedViewKeyError::BadSignature)
        );
    }
}
