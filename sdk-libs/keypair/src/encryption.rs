use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::SecretKey;
use sha2::Sha256;

use crate::constants::{ENC_INFO_TRANSFER, GCM_NONCE_LEN, HPKE_PREFIX, P256_PUBKEY_LEN};
use crate::error::Error;
use crate::pubkey::P256Pubkey;

pub(crate) fn ecdh_x(sk: &SecretKey, pubkey: &P256Pubkey) -> [u8; 32] {
    let shared = diffie_hellman(sk.to_nonzero_scalar(), pubkey.to_p256().as_affine());
    let mut x = [0u8; 32];
    x.copy_from_slice(shared.raw_secret_bytes().as_slice());
    x
}

fn key_schedule(
    dh: &[u8; 32],
    ephemeral_pubkey: &P256Pubkey,
    recipient_pubkey: &P256Pubkey,
    info: &[u8],
) -> Result<([u8; 32], [u8; GCM_NONCE_LEN]), Error> {
    let mut ikm = [0u8; 32 + 2 * P256_PUBKEY_LEN];
    ikm[..32].copy_from_slice(dh);
    ikm[32..32 + P256_PUBKEY_LEN].copy_from_slice(ephemeral_pubkey.as_bytes());
    ikm[32 + P256_PUBKEY_LEN..].copy_from_slice(recipient_pubkey.as_bytes());

    let mut okm = [0u8; 32 + GCM_NONCE_LEN];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand_multi_info(&[HPKE_PREFIX, info], &mut okm)
        .map_err(|_| Error::Hkdf)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; GCM_NONCE_LEN];
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

fn seal(
    key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Aead)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Aead)
}

fn open(
    key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Aead)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Aead)
}

pub(crate) fn encrypt(
    ephemeral_sk: &SecretKey,
    recipient_pubkey: &P256Pubkey,
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let ephemeral_pubkey = P256Pubkey::from_p256(&ephemeral_sk.public_key());
    let dh = ecdh_x(ephemeral_sk, recipient_pubkey);
    let (key, nonce) = key_schedule(&dh, &ephemeral_pubkey, recipient_pubkey, info)?;
    seal(&key, &nonce, plaintext, aad)
}

pub(crate) fn decrypt(
    viewing_sk: &SecretKey,
    ephemeral_pubkey: &P256Pubkey,
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let recipient_pubkey = P256Pubkey::from_p256(&viewing_sk.public_key());
    let dh = ecdh_x(viewing_sk, ephemeral_pubkey);
    let (key, nonce) = key_schedule(&dh, ephemeral_pubkey, &recipient_pubkey, info)?;
    open(&key, &nonce, ciphertext, aad)
}

pub(crate) fn encrypt_transfer(
    ephemeral_sk: &SecretKey,
    recipient_pubkey: &P256Pubkey,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    encrypt(
        ephemeral_sk,
        recipient_pubkey,
        plaintext,
        ENC_INFO_TRANSFER,
        &[],
    )
}

pub(crate) fn decrypt_transfer(
    viewing_sk: &SecretKey,
    ephemeral_pubkey: &P256Pubkey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    decrypt(
        viewing_sk,
        ephemeral_pubkey,
        ciphertext,
        ENC_INFO_TRANSFER,
        &[],
    )
}
