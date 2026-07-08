//! Seed a fully populated [`ViewingKeyAccount`] without a prover.
//!
//! The on-chain create path proves the ciphertexts via the key-encryption proof
//! (`prover/key_encryption.rs`); tests and fixtures that only need the account
//! bytes (so the backend can recover the shared key with the auditor secret) can
//! build the same ciphertexts directly from the pure-crypto gadgets. The output
//! round-trips through [`recover_shared_secret`] /
//! [`recover_nullifier_secret`](zolana_squads_sdk::viewing_key_account::recover_nullifier_secret).

use p256::SecretKey;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{P256Pubkey, ViewingKey};
use zolana_squads_interface::{
    state::ViewingKeyAccount,
    types::{Address, EncryptedNullifierSecret, SharedKeyCiphertext},
};
use zolana_squads_sdk::crypto;

use crate::error::{Result, SquadsBackendError};

/// Scalar fields of a seeded viewing key account.
#[derive(Clone, Copy, Debug)]
pub struct ViewingKeyAccountSeed {
    pub owner: Address,
    pub owner_kind: u8,
    pub state: u8,
    pub encryption_scheme: u8,
    pub key_nonce: u64,
}

fn crypto_err(e: crypto::CryptoError) -> SquadsBackendError {
    SquadsBackendError::Crypto(format!("{e:?}"))
}

fn to_shared_ct(bytes: Vec<u8>) -> Result<SharedKeyCiphertext> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| SquadsBackendError::Crypto("shared key ciphertext length".into()))
}

/// Encrypt `viewing_sk_be` to `recipient` under `ephemeral`, matching
/// `KeyEncryptionWitness::prove`'s per-recipient ciphertext.
fn encrypt_shared_key(
    ephemeral_sk: &SecretKey,
    ephemeral_comp: &[u8; 33],
    recipient: &P256Pubkey,
    viewing_sk_be: &[u8; 32],
) -> Result<SharedKeyCiphertext> {
    let dh = ViewingKey::from_secret_key(ephemeral_sk.clone())
        .ecdh(recipient)
        .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
    let ciphertext = crypto::ecdh_encrypt(&dh, ephemeral_comp, recipient.as_bytes(), viewing_sk_be)
        .map_err(crypto_err)?;
    to_shared_ct(ciphertext)
}

/// Build a viewing key account whose shared viewing secret is recoverable by each
/// recovery key and each auditor key, and whose nullifier secret is encrypted to
/// the shared viewing key. `nullifier_secret` is the 32-byte field element; its
/// low 31 bytes are what the account stores.
pub fn seed_viewing_key_account(
    seed: ViewingKeyAccountSeed,
    shared_viewing_sk: &SecretKey,
    ephemeral_sk: &SecretKey,
    nullifier_secret: &[u8; 32],
    recovery_keys: &[P256Pubkey],
    auditor_keys: &[P256Pubkey],
) -> Result<ViewingKeyAccount> {
    let shared_viewing_pk = P256Pubkey::from_p256(&shared_viewing_sk.public_key());
    let ephemeral_pk = P256Pubkey::from_p256(&ephemeral_sk.public_key());
    let ephemeral_comp = *ephemeral_pk.as_bytes();

    let mut viewing_sk_be = [0u8; 32];
    viewing_sk_be.copy_from_slice(shared_viewing_sk.to_bytes().as_slice());

    let commitment = crypto::hash_field(&viewing_sk_be).map_err(crypto_err)?;

    let recovery_key_ciphertexts = recovery_keys
        .iter()
        .map(|pk| encrypt_shared_key(ephemeral_sk, &ephemeral_comp, pk, &viewing_sk_be))
        .collect::<Result<Vec<_>>>()?;
    let auditor_key_ciphertexts = auditor_keys
        .iter()
        .map(|pk| encrypt_shared_key(ephemeral_sk, &ephemeral_comp, pk, &viewing_sk_be))
        .collect::<Result<Vec<_>>>()?;

    let nullifier_pubkey = Poseidon::hashv(&[nullifier_secret.as_slice()])
        .map_err(|e| SquadsBackendError::Crypto(format!("poseidon: {e:?}")))?;
    let null_plaintext = nullifier_secret
        .get(1..32)
        .ok_or_else(|| SquadsBackendError::Crypto("nullifier secret length".into()))?;
    let dh_null = ViewingKey::from_secret_key(ephemeral_sk.clone())
        .ecdh(&shared_viewing_pk)
        .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
    let nullifier_ciphertext = crypto::ecdh_encrypt(
        &dh_null,
        &ephemeral_comp,
        shared_viewing_pk.as_bytes(),
        null_plaintext,
    )
    .map_err(crypto_err)?;
    let encrypted_nullifier_secret: EncryptedNullifierSecret = nullifier_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| SquadsBackendError::Crypto("nullifier ciphertext length".into()))?;

    Ok(ViewingKeyAccount {
        discriminator: ViewingKeyAccount::DISCRIMINATOR,
        owner: seed.owner,
        state: seed.state,
        encryption_scheme: seed.encryption_scheme,
        owner_kind: seed.owner_kind,
        shared_viewing_key: *shared_viewing_pk.as_bytes(),
        shared_viewing_key_commitment: commitment,
        key_nonce: seed.key_nonce,
        nullifier_pubkey,
        key_ciphertext_ephemeral: *ephemeral_pk.as_bytes(),
        encrypted_nullifier_secret,
        recovery_keys: recovery_keys.iter().map(|pk| *pk.as_bytes()).collect(),
        recovery_key_ciphertexts,
        auditor_keys: auditor_keys.iter().map(|pk| *pk.as_bytes()).collect(),
        auditor_key_ciphertexts,
    })
}
