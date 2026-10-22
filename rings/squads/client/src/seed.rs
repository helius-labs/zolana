//! Seed a fully populated [`ViewingKeyAccount`] without a prover.
//!
//! The on-chain create path proves the ciphertexts via the key-encryption proof
//! (`prover/key_encryption.rs`); tests and fixtures that only need the account
//! bytes (so the backend can recover the shared key with the auditor secret) can
//! build the same ciphertexts directly from the pure-crypto gadgets. The output
//! round-trips through [`recover_shared_secret`] /
//! [`recover_nullifier_secret`](zolana_squads_sdk::viewing_key_account::recover_nullifier_secret).

use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::X25519Keypair;
use zolana_keypair::X25519Pubkey;
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

/// Encrypt `viewing_secret_bytes` to `recipient` under `ephemeral`, matching
/// `KeyEncryptionWitness::prove`'s per-recipient ciphertext.
fn encrypt_shared_key(
    ephemeral_sk: &X25519Keypair,
    ephemeral_comp: &[u8; 33],
    recipient: &X25519Pubkey,
    viewing_secret_bytes: &[u8; 32],
) -> Result<SharedKeyCiphertext> {
    let dh = ephemeral_sk
        .ecdh(recipient)
        .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
    let ciphertext = crypto::ecdh_encrypt(
        &dh,
        ephemeral_comp,
        recipient.as_bytes(),
        viewing_secret_bytes,
        crypto::SHARED_KEY_INFO,
    )
    .map_err(crypto_err)?;
    to_shared_ct(ciphertext)
}

/// Build a viewing key account whose shared viewing secret is recoverable by each
/// recovery key and each auditor key, and whose nullifier secret is encrypted to
/// the shared viewing key. `nullifier_secret` is the 32-byte field element; its
/// low 31 bytes are what the account stores.
pub fn seed_viewing_key_account(
    seed: ViewingKeyAccountSeed,
    shared_viewing_sk: &X25519Keypair,
    ephemeral_sk: &X25519Keypair,
    nullifier_secret: &[u8; 32],
    recovery_keys: &[X25519Pubkey],
    auditor_keys: &[X25519Pubkey],
) -> Result<ViewingKeyAccount> {
    let shared_viewing_pk = shared_viewing_sk.pubkey();
    let ephemeral_pk = ephemeral_sk.pubkey();
    let ephemeral_comp = *ephemeral_pk.as_bytes();

    let mut viewing_secret_bytes = [0u8; 32];
    viewing_secret_bytes.copy_from_slice(shared_viewing_sk.secret_bytes().as_slice());

    let commitment = crypto::hash_field(&viewing_secret_bytes).map_err(crypto_err)?;

    let recovery_key_ciphertexts = recovery_keys
        .iter()
        .map(|pk| encrypt_shared_key(ephemeral_sk, &ephemeral_comp, pk, &viewing_secret_bytes))
        .collect::<Result<Vec<_>>>()?;
    let auditor_key_ciphertexts = auditor_keys
        .iter()
        .map(|pk| encrypt_shared_key(ephemeral_sk, &ephemeral_comp, pk, &viewing_secret_bytes))
        .collect::<Result<Vec<_>>>()?;

    let nullifier_pubkey = Poseidon::hashv(&[nullifier_secret.as_slice()])
        .map_err(|e| SquadsBackendError::Crypto(format!("poseidon: {e:?}")))?;
    let null_plaintext = nullifier_secret
        .get(1..32)
        .ok_or_else(|| SquadsBackendError::Crypto("nullifier secret length".into()))?;
    let dh_null = ephemeral_sk
        .ecdh(&shared_viewing_pk)
        .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))?;
    let nullifier_ciphertext = crypto::ecdh_encrypt(
        &dh_null,
        &ephemeral_comp,
        shared_viewing_pk.as_bytes(),
        null_plaintext,
        crypto::NULLIFIER_INFO,
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
