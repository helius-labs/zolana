use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::{AffinePoint, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::constants::{ENC_INFO_TRANSFER, GCM_NONCE_LEN, HPKE_PREFIX, P256_PUBKEY_LEN, SALT_LEN};
use crate::error::KeypairError;
use crate::pubkey::P256Pubkey;

pub(crate) fn ecdh_x(
    secret_key: &SecretKey,
    pubkey: &P256Pubkey,
) -> Result<[u8; 32], KeypairError> {
    Ok(ecdh_x_point(secret_key, pubkey.to_p256()?.as_affine()))
}

pub(crate) fn ecdh_x_point(secret_key: &SecretKey, point: &AffinePoint) -> [u8; 32] {
    let shared = diffie_hellman(secret_key.to_nonzero_scalar(), point);
    let mut x = [0u8; 32];
    x.copy_from_slice(shared.raw_secret_bytes().as_slice());
    x
}

// TODO: try to use a library directly and ensure HSM and yubikey compatibility (different pr)
fn derive_key_nonce(
    dh: &[u8; 32],
    ephemeral_pubkey: &P256Pubkey,
    recipient_pubkey: &P256Pubkey,
    info: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<(Zeroizing<[u8; 32]>, [u8; GCM_NONCE_LEN]), KeypairError> {
    let mut ikm = Zeroizing::new([0u8; 32 + 2 * P256_PUBKEY_LEN]);
    ikm[..32].copy_from_slice(dh);
    ikm[32..32 + P256_PUBKEY_LEN].copy_from_slice(ephemeral_pubkey.as_bytes());
    ikm[32 + P256_PUBKEY_LEN..].copy_from_slice(recipient_pubkey.as_bytes());

    let mut okm = Zeroizing::new([0u8; 32 + GCM_NONCE_LEN]);
    Hkdf::<Sha256>::new(None, ikm.as_slice())
        .expand_multi_info(
            &[HPKE_PREFIX, info, salt, &slot.to_be_bytes()],
            okm.as_mut_slice(),
        )
        .map_err(|_| KeypairError::Hkdf)?;
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; GCM_NONCE_LEN];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

pub(crate) fn encrypt(
    ephemeral_secret_key: &SecretKey,
    recipient_pubkey: &P256Pubkey,
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<Vec<u8>, KeypairError> {
    let ephemeral_pubkey = P256Pubkey::from_p256(&ephemeral_secret_key.public_key());
    let dh = Zeroizing::new(ecdh_x(ephemeral_secret_key, recipient_pubkey)?);
    let (key, nonce) =
        derive_key_nonce(&dh, &ephemeral_pubkey, recipient_pubkey, info, salt, slot)?;
    let cipher = Aes256Gcm::new(&(*key).into());
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeypairError::Aead)
}

pub(crate) fn decrypt(
    viewing_secret_key: &SecretKey,
    ephemeral_pubkey: &P256Pubkey,
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<Vec<u8>, KeypairError> {
    let recipient_pubkey = P256Pubkey::from_p256(&viewing_secret_key.public_key());
    let dh = Zeroizing::new(ecdh_x(viewing_secret_key, ephemeral_pubkey)?);
    let (key, nonce) =
        derive_key_nonce(&dh, ephemeral_pubkey, &recipient_pubkey, info, salt, slot)?;
    let cipher = Aes256Gcm::new(&(*key).into());
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| KeypairError::Aead)
}

pub(crate) fn decrypt_ephemeral(
    ephemeral_secret_key: &SecretKey,
    recipient_pubkey: &P256Pubkey,
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<Vec<u8>, KeypairError> {
    let ephemeral_pubkey = P256Pubkey::from_p256(&ephemeral_secret_key.public_key());
    let dh = Zeroizing::new(ecdh_x(ephemeral_secret_key, recipient_pubkey)?);
    let (key, nonce) =
        derive_key_nonce(&dh, &ephemeral_pubkey, recipient_pubkey, info, salt, slot)?;
    let cipher = Aes256Gcm::new(&(*key).into());
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| KeypairError::Aead)
}

pub(crate) fn encrypt_utxo(
    ephemeral_secret_key: &SecretKey,
    recipient_pubkey: &P256Pubkey,
    plaintext: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<Vec<u8>, KeypairError> {
    encrypt(
        ephemeral_secret_key,
        recipient_pubkey,
        plaintext,
        ENC_INFO_TRANSFER,
        &[],
        salt,
        slot,
    )
}

pub(crate) fn decrypt_utxo(
    viewing_secret_key: &SecretKey,
    ephemeral_pubkey: &P256Pubkey,
    ciphertext: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<Vec<u8>, KeypairError> {
    decrypt(
        viewing_secret_key,
        ephemeral_pubkey,
        ciphertext,
        ENC_INFO_TRANSFER,
        &[],
        salt,
        slot,
    )
}

pub(crate) fn decrypt_utxo_ephemeral(
    ephemeral_secret_key: &SecretKey,
    recipient_pubkey: &P256Pubkey,
    ciphertext: &[u8],
    salt: &[u8; SALT_LEN],
    slot: u32,
) -> Result<Vec<u8>, KeypairError> {
    decrypt_ephemeral(
        ephemeral_secret_key,
        recipient_pubkey,
        ciphertext,
        ENC_INFO_TRANSFER,
        &[],
        salt,
        slot,
    )
}
