//! A Turnkey backend driving a wallet through [`KeypairWalletAuthority`].
//!
//! The backends implement `ShieldedKeypairTrait`, but the wallet consumes
//! `WalletAuthority`. This is the join: it fails to compile if the generic
//! authority stops accepting a foreign keypair, and fails at runtime if the
//! remote identity drifts from the software one.

use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signer as _, SigningKey as DalekSigningKey};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature as EcdsaSignature};
use zolana_keypair::{hash, NullifierKey, P256Pubkey, ShieldedKeypair, SigningKey, ViewingKey};
use zolana_keypair_turnkey::{
    PayloadHashFunction, RawSignature, RemoteKey, TurnkeyActivities, TurnkeyCurve,
    TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef, TurnkeyKeypairError, TurnkeyP256ShieldedKeypair,
};
use zolana_transaction::{
    Address, AssetRegistry, KeypairWalletAuthority, SyncWalletAuthority, TransactionError,
};

const ED25519_SECRET: [u8; 32] = [11u8; 32];
const P256_SIGN_SECRET: [u8; 32] = [21u8; 32];
const P256_VIEWING_SECRET: [u8; 32] = [22u8; 32];
const P256_NULLIFIER_SECRET: [u8; 31] = [23u8; 31];

const ORGANIZATION_ID: &str = "sub-org";
const KEY_ID: &str = "private-key";

/// Minimal in-process stand-in; the transport-level behaviours are covered in
/// `turnkey_backends.rs`.
enum MockTurnkey {
    Ed25519(Box<DalekSigningKey>),
    P256(p256::SecretKey),
}

#[async_trait]
impl TurnkeyActivities for MockTurnkey {
    async fn get_private_key(
        &self,
        _organization_id: &str,
        _private_key_id: &str,
    ) -> Result<RemoteKey, TurnkeyKeypairError> {
        Ok(match self {
            Self::Ed25519(key) => RemoteKey {
                curve: TurnkeyCurve::Ed25519,
                public_key: key.verifying_key().as_bytes().to_vec(),
            },
            Self::P256(key) => RemoteKey {
                curve: TurnkeyCurve::P256,
                public_key: P256Pubkey::from_p256(&key.public_key()).as_bytes().to_vec(),
            },
        })
    }

    async fn sign_raw_payload(
        &self,
        _organization_id: &str,
        _private_key_id: &str,
        payload: &[u8],
        _hash_function: PayloadHashFunction,
    ) -> Result<RawSignature, TurnkeyKeypairError> {
        let signature: [u8; 64] = match self {
            Self::Ed25519(key) => key.sign(payload).to_bytes(),
            Self::P256(key) => {
                let signing = p256::ecdsa::SigningKey::from(key);
                let signature: EcdsaSignature =
                    signing.sign_prehash(payload).expect("prehash signing");
                signature.to_bytes().into()
            }
        };
        let (r, s) = signature.split_at(32);
        Ok(RawSignature {
            r: r.to_vec(),
            s: s.to_vec(),
        })
    }
}

fn key_ref() -> TurnkeyKeyRef {
    TurnkeyKeyRef::new(ORGANIZATION_ID, KEY_ID)
}

fn software_ed25519() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&ED25519_SECRET))
        .expect("software keypair")
}

async fn ed25519_backend() -> TurnkeyEd25519ShieldedKeypair {
    TurnkeyEd25519ShieldedKeypair::bootstrap(
        Arc::new(MockTurnkey::Ed25519(Box::new(DalekSigningKey::from_bytes(
            &ED25519_SECRET,
        )))),
        key_ref(),
    )
    .await
    .expect("bootstrap")
}

async fn p256_backend() -> TurnkeyP256ShieldedKeypair {
    TurnkeyP256ShieldedKeypair::bootstrap_with_roles(
        Arc::new(MockTurnkey::P256(
            p256::SecretKey::from_slice(&P256_SIGN_SECRET).expect("P-256 scalar"),
        )),
        key_ref(),
        NullifierKey::from_secret(P256_NULLIFIER_SECRET),
        ViewingKey::from_bytes(&P256_VIEWING_SECRET).expect("viewing key"),
    )
    .await
    .expect("bootstrap")
}

/// The identity and scan material a wallet reads through the authority are the
/// software keypair's, unchanged by the signing key living in Turnkey.
#[tokio::test]
async fn ed25519_backend_drives_a_wallet_authority() {
    let backend = ed25519_backend().await;
    let software = software_ed25519();

    let authority = KeypairWalletAuthority::with_viewing_keys(
        backend.solana_address(),
        &backend,
        vec![backend.viewing_key().clone()],
    )
    .expect("the backend supplies its own viewing key");
    let reference = KeypairWalletAuthority::new(backend.solana_address(), &software);

    assert_eq!(
        SyncWalletAuthority::shielded_address(&authority).unwrap(),
        SyncWalletAuthority::shielded_address(&reference).unwrap()
    );
    assert_eq!(
        SyncWalletAuthority::solana_pubkey(&authority),
        Address::new_from_array(software.signing_pubkey().as_ed25519().unwrap())
    );
    assert_eq!(
        SyncWalletAuthority::spend_nullifier_key(&authority)
            .unwrap()
            .pubkey()
            .unwrap(),
        software.nullifier_key.pubkey().unwrap()
    );

    // `sync_material` is the whole snapshot a scan takes; its viewing key must
    // be the one in the published identity or the scan refuses to run.
    let material = SyncWalletAuthority::sync_material(&authority).unwrap();
    assert!(material
        .viewing_keys
        .iter()
        .any(|key| key.pubkey() == material.identity.viewing_pubkey));
}

/// The encryption bodies run over the Turnkey backend untouched: the
/// per-transaction viewing key matches the software path. Only `tx_viewing_pk`
/// is deterministic here — the salt is fresh per call.
#[tokio::test]
async fn ed25519_backend_encrypts_through_the_authority() {
    let backend = ed25519_backend().await;
    let software = software_ed25519();
    let first_nullifier = [4u8; 32];
    let assets = AssetRegistry::default();

    let from_backend = SyncWalletAuthority::encrypt_confidential_transfer(
        &KeypairWalletAuthority::with_viewing_keys(
            Address::default(),
            &backend,
            vec![backend.viewing_key().clone()],
        )
        .expect("the backend supplies its own viewing key"),
        &first_nullifier,
        &[],
        &assets,
    )
    .unwrap();
    let from_software = SyncWalletAuthority::encrypt_confidential_transfer(
        &KeypairWalletAuthority::new(Address::default(), &software),
        &first_nullifier,
        &[],
        &assets,
    )
    .unwrap();

    assert_eq!(from_backend.tx_viewing_pk, from_software.tx_viewing_pk);
}

/// Shielded spend authorization on the P-256 rail goes through the authority to
/// Turnkey, and matches the software signature (ECDSA here is deterministic).
#[tokio::test]
async fn p256_backend_signs_a_spend_through_the_authority() {
    let backend = p256_backend().await;
    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::default(),
        &backend,
        vec![backend.viewing_key().clone()],
    )
    .expect("the backend supplies its own viewing key");
    let message_hash = hash::sha256(b"private tx hash binding");

    let signature = SyncWalletAuthority::sign_p256(&authority, &message_hash).unwrap();

    let software = SigningKey::from_p256_bytes(&P256_SIGN_SECRET).unwrap();
    assert_eq!(signature.pubkey, software.pubkey().as_p256().unwrap());
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&signature.sig_r);
    bytes[32..].copy_from_slice(&signature.sig_s);
    assert!(software.pubkey().verify_hash(&message_hash, &bytes));
}

/// An ed25519 owner has no P-256 spend signature: it authorizes by signing the
/// Solana transaction instead. `sign_hash` refuses on the rail check, so the
/// authority errors without ever reaching Turnkey — not a silently wrong
/// signature, and not a wasted remote call.
#[tokio::test]
async fn ed25519_backend_has_no_p256_spend_signature() {
    let backend = ed25519_backend().await;
    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::default(),
        &backend,
        vec![backend.viewing_key().clone()],
    )
    .expect("the backend supplies its own viewing key");

    assert!(matches!(
        SyncWalletAuthority::sign_p256(&authority, &[6u8; 32]),
        Err(TransactionError::P256(_))
    ));
}
