//! Backend tests over an in-process Turnkey stand-in.
//!
//! The mock replaces only the transport, so the code under test is the same code
//! that talks to the live API. The central property is byte-for-byte parity with
//! a software [`ShieldedKeypair`]: a remote backend that derives a *different*
//! identity still produces valid signatures and correct-looking addresses, so
//! nothing but an equality check against the software path catches it.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;
use ed25519_dalek::{Signer as _, SigningKey as DalekSigningKey};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature as EcdsaSignature};
use zolana_keypair::{
    derivation::{
        ed25519_derivation_message, expand_roles, DERIVATION_PAYLOAD_PREFIX, ED25519_DERIVATION_MSG,
    },
    hash, Curve, KeypairError, NullifierKey, P256Pubkey, ShieldedKeypair, ShieldedKeypairTrait,
    SigningKey, ViewingKey,
};
use zolana_keypair_turnkey::{
    PayloadHashFunction, RawSignature, RemoteKey, TurnkeyActivities, TurnkeyCurve,
    TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef, TurnkeyKeypairError, TurnkeyP256ShieldedKeypair,
};

const ED25519_SECRET: [u8; 32] = [11u8; 32];
const P256_SIGN_SECRET: [u8; 32] = [21u8; 32];
const P256_VIEWING_SECRET: [u8; 32] = [22u8; 32];
const P256_NULLIFIER_SECRET: [u8; 31] = [23u8; 31];

const ORGANIZATION_ID: &str = "sub-org-under-test";
const KEY_ID: &str = "private-key-under-test";

// --- the stand-in -----------------------------------------------------------

/// How the mock deviates from a well-behaved Turnkey.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Behavior {
    #[default]
    Normal,
    /// Drops the leading byte of `r`, the shape a naive client would silently
    /// left-pad back to width.
    TruncateR,
    /// Signs the derivation envelope with a key other than the one it publishes.
    ForeignSeedSignature,
    /// Serves the derivation seed, then fails every later request.
    FailAfterBootstrap,
    /// Returns a high-S ECDSA signature.
    HighS,
}

enum MockKey {
    Ed25519(Box<DalekSigningKey>),
    P256(p256::SecretKey),
}

struct MockTurnkey {
    key: MockKey,
    reported_curve: TurnkeyCurve,
    reported_public_key: Vec<u8>,
    behavior: Behavior,
    get_private_key_calls: AtomicUsize,
    sign_calls: AtomicUsize,
    requests: Mutex<Vec<(Vec<u8>, PayloadHashFunction)>>,
}

impl MockTurnkey {
    fn ed25519(secret: &[u8; 32]) -> Self {
        let key = DalekSigningKey::from_bytes(secret);
        let reported_public_key = key.verifying_key().as_bytes().to_vec();
        Self {
            key: MockKey::Ed25519(Box::new(key)),
            reported_curve: TurnkeyCurve::Ed25519,
            reported_public_key,
            behavior: Behavior::Normal,
            get_private_key_calls: AtomicUsize::new(0),
            sign_calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn p256(secret: &[u8; 32]) -> Self {
        let key = p256::SecretKey::from_slice(secret).expect("valid P-256 scalar");
        let reported_public_key = P256Pubkey::from_p256(&key.public_key()).as_bytes().to_vec();
        Self {
            key: MockKey::P256(key),
            reported_curve: TurnkeyCurve::P256,
            reported_public_key,
            behavior: Behavior::Normal,
            get_private_key_calls: AtomicUsize::new(0),
            sign_calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn with_behavior(mut self, behavior: Behavior) -> Self {
        self.behavior = behavior;
        self
    }

    fn with_reported_curve(mut self, curve: TurnkeyCurve) -> Self {
        self.reported_curve = curve;
        self
    }

    fn with_reported_public_key(mut self, public_key: Vec<u8>) -> Self {
        self.reported_public_key = public_key;
        self
    }

    fn hash_functions(&self) -> Vec<PayloadHashFunction> {
        self.requests
            .lock()
            .expect("uncontended")
            .iter()
            .map(|(_, hash_function)| *hash_function)
            .collect()
    }

    fn signed_payloads(&self) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .expect("uncontended")
            .iter()
            .map(|(payload, _)| payload.clone())
            .collect()
    }
}

/// Splits a 64-byte signature the way Turnkey reports it: two components, each
/// full width. `TruncateR` models a provider that strips a byte instead.
fn components(signature: &[u8; 64], behavior: Behavior) -> RawSignature {
    let (r, s) = signature.split_at(32);
    RawSignature {
        r: match behavior {
            Behavior::TruncateR => r.get(1..).expect("32-byte component").to_vec(),
            _ => r.to_vec(),
        },
        s: s.to_vec(),
    }
}

#[async_trait]
impl TurnkeyActivities for MockTurnkey {
    async fn get_private_key(
        &self,
        organization_id: &str,
        private_key_id: &str,
    ) -> Result<RemoteKey, TurnkeyKeypairError> {
        assert_eq!(organization_id, ORGANIZATION_ID);
        assert_eq!(private_key_id, KEY_ID);
        self.get_private_key_calls.fetch_add(1, Ordering::SeqCst);
        Ok(RemoteKey {
            curve: self.reported_curve,
            public_key: self.reported_public_key.clone(),
        })
    }

    async fn sign_raw_payload(
        &self,
        organization_id: &str,
        private_key_id: &str,
        payload: &[u8],
        hash_function: PayloadHashFunction,
    ) -> Result<RawSignature, TurnkeyKeypairError> {
        assert_eq!(organization_id, ORGANIZATION_ID);
        assert_eq!(private_key_id, KEY_ID);
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("uncontended")
            .push((payload.to_vec(), hash_function));

        let is_seed = zolana_keypair::derivation::is_derivation_input(payload);
        if self.behavior == Behavior::FailAfterBootstrap && !is_seed {
            return Err(TurnkeyKeypairError::Transport(
                "key pending deletion".into(),
            ));
        }

        match &self.key {
            MockKey::Ed25519(key) => {
                let key = if self.behavior == Behavior::ForeignSeedSignature && is_seed {
                    DalekSigningKey::from_bytes(&[99u8; 32])
                } else {
                    DalekSigningKey::from_bytes(&key.to_bytes())
                };
                Ok(components(&key.sign(payload).to_bytes(), self.behavior))
            }
            MockKey::P256(secret) => {
                let signing = p256::ecdsa::SigningKey::from(secret);
                let signature: EcdsaSignature = signing
                    .sign_prehash(payload)
                    .expect("P-256 prehash signing");
                let signature = match self.behavior {
                    Behavior::HighS => high_s(&signature),
                    _ => signature,
                };
                Ok(components(&signature.to_bytes().into(), self.behavior))
            }
        }
    }
}

fn high_s(signature: &EcdsaSignature) -> EcdsaSignature {
    use p256::elliptic_curve::scalar::IsHigh;

    let s = *signature.s();
    let flipped = if s.is_high().into() { s } else { -s };
    EcdsaSignature::from_scalars(*signature.r(), flipped).expect("nonzero scalars")
}

fn key_ref() -> TurnkeyKeyRef {
    TurnkeyKeyRef::new(ORGANIZATION_ID, KEY_ID)
}

fn software_ed25519() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&ED25519_SECRET))
        .expect("software keypair")
}

async fn bootstrap_ed25519(
    mock: Arc<MockTurnkey>,
) -> Result<TurnkeyEd25519ShieldedKeypair, TurnkeyKeypairError> {
    TurnkeyEd25519ShieldedKeypair::bootstrap(mock, key_ref()).await
}

fn supplied_roles() -> (NullifierKey, ViewingKey) {
    (
        NullifierKey::from_secret(P256_NULLIFIER_SECRET),
        ViewingKey::from_bytes(&P256_VIEWING_SECRET).expect("viewing key"),
    )
}

async fn bootstrap_p256(
    mock: Arc<MockTurnkey>,
) -> Result<TurnkeyP256ShieldedKeypair, TurnkeyKeypairError> {
    let (nullifier_key, viewing_key) = supplied_roles();
    TurnkeyP256ShieldedKeypair::bootstrap_with_roles(mock, key_ref(), nullifier_key, viewing_key)
        .await
}

// --- ed25519 rail -----------------------------------------------------------

/// The whole point of the rail: an identity rooted in Turnkey is bit-identical
/// to the software one, so a wallet can move between them.
#[tokio::test]
async fn ed25519_backend_matches_software_keypair() {
    let mock = Arc::new(MockTurnkey::ed25519(&ED25519_SECRET));
    let turnkey = bootstrap_ed25519(mock.clone()).await.unwrap();
    let software = software_ed25519();

    assert_eq!(turnkey.signing_pubkey(), software.signing_pubkey());
    assert_eq!(turnkey.viewing_pubkey(), software.viewing_pubkey());
    assert_eq!(turnkey.curve(), Curve::Ed25519);
    assert_eq!(
        turnkey.shielded_address().unwrap(),
        software.shielded_address().unwrap()
    );
    assert_eq!(
        turnkey.owner_hash().unwrap(),
        software.owner_hash().unwrap()
    );
    assert_eq!(
        turnkey.compressed_address().unwrap(),
        software.compressed_address().unwrap()
    );
    assert_eq!(
        *turnkey.nullifier_key().secret(),
        *software.nullifier_key.secret()
    );
    assert_eq!(
        turnkey.nullifier_pubkey().unwrap(),
        software.nullifier_key.pubkey().unwrap()
    );

    let utxo_hash = [1u8; 32];
    let blinding = [2u8; 32];
    assert_eq!(
        turnkey.nullifier(&utxo_hash, &blinding).unwrap(),
        software.nullifier(&utxo_hash, &blinding).unwrap()
    );

    // The Solana address of the same key, which is the wallet's owner-signer.
    assert_eq!(
        turnkey.solana_address().to_bytes(),
        software.signing_pubkey().as_ed25519().unwrap()
    );

    // Bootstrap costs exactly one read and one signature, and nothing since.
    assert_eq!(mock.get_private_key_calls.load(Ordering::SeqCst), 1);
    assert_eq!(mock.sign_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.hash_functions(),
        vec![PayloadHashFunction::NotApplicable]
    );
}

/// Bootstrap signs the off-chain-encoded envelope, not the bare payload. The two
/// derive different seeds, so this pins the exact bytes.
#[tokio::test]
async fn ed25519_bootstrap_signs_the_offchain_envelope() {
    let mock = Arc::new(MockTurnkey::ed25519(&ED25519_SECRET));
    let turnkey = bootstrap_ed25519(mock.clone()).await.unwrap();

    let expected = ed25519_derivation_message(&turnkey.signing_pubkey().as_ed25519().unwrap());
    assert_eq!(mock.signed_payloads(), vec![expected.clone()]);
    assert_ne!(expected, ED25519_DERIVATION_MSG.to_vec());
}

/// Recovery: the key reference alone rebuilds the identity, which is the claim
/// that lets a service persist no secret at all.
#[tokio::test]
async fn ed25519_backend_rebuilds_the_same_identity_from_the_key_reference() {
    let first = bootstrap_ed25519(Arc::new(MockTurnkey::ed25519(&ED25519_SECRET)))
        .await
        .unwrap();
    let second = bootstrap_ed25519(Arc::new(MockTurnkey::ed25519(&ED25519_SECRET)))
        .await
        .unwrap();

    assert_eq!(first.key_ref(), second.key_ref());
    assert_eq!(
        first.shielded_address().unwrap(),
        second.shielded_address().unwrap()
    );
    assert_eq!(
        *first.nullifier_key().secret(),
        *second.nullifier_key().secret()
    );
}

/// Remote signatures equal software signatures, and the derivation payload is
/// refused in both its bare and envelope forms without reaching Turnkey.
#[tokio::test]
async fn ed25519_backend_signs_like_software_and_guards_derivation_inputs() {
    let mock = Arc::new(MockTurnkey::ed25519(&ED25519_SECRET));
    let turnkey = bootstrap_ed25519(mock.clone()).await.unwrap();
    let software = software_ed25519();

    let msg = b"private tx hash binding";
    let signature = turnkey.sign_message_async(msg).await.unwrap();
    assert_eq!(signature, software.sign_message(msg).unwrap());
    assert!(turnkey.signing_pubkey().verify_message(msg, &signature));
    assert_eq!(mock.sign_calls.load(Ordering::SeqCst), 2);

    let signer = software.signing_pubkey().as_ed25519().unwrap();
    for guarded in [
        ED25519_DERIVATION_MSG.to_vec(),
        ed25519_derivation_message(&signer),
    ] {
        assert!(matches!(
            turnkey.sign_message_async(&guarded).await,
            Err(TurnkeyKeypairError::Keypair(KeypairError::DerivationInput))
        ));
        assert_eq!(
            ShieldedKeypairTrait::sign_message(&turnkey, &guarded),
            Err(KeypairError::DerivationInput)
        );
    }
    // Refused locally: no request was made for any of them.
    assert_eq!(mock.sign_calls.load(Ordering::SeqCst), 2);

    // The digest path belongs to the P-256 rail. An ed25519 owner authorizes a
    // spend with a Solana transaction signature, so this refuses on the rail
    // check rather than signing digest bytes that no proof would accept.
    assert_eq!(
        ShieldedKeypairTrait::sign_hash(&turnkey, &[7u8; 32]),
        Err(KeypairError::NotP256)
    );
    assert_eq!(mock.sign_calls.load(Ordering::SeqCst), 2);
}

/// A truncated component is rejected rather than padded — and the same test
/// shows what padding would have cost: a different, perfectly valid wallet.
#[tokio::test]
async fn ed25519_bootstrap_rejects_a_truncated_component_instead_of_padding_it() {
    let mock = Arc::new(MockTurnkey::ed25519(&ED25519_SECRET).with_behavior(Behavior::TruncateR));

    let error = bootstrap_ed25519(mock).await.expect_err("must not derive");
    assert!(matches!(
        error,
        TurnkeyKeypairError::MalformedResponse { .. }
    ));

    // What a left-pad would have produced, had the error not been raised.
    let software = software_ed25519();
    let signer = software.signing_pubkey().as_ed25519().unwrap();
    let seed = DalekSigningKey::from_bytes(&ED25519_SECRET)
        .sign(&ed25519_derivation_message(&signer))
        .to_bytes();
    let mut padded = [0u8; 64];
    padded[1..32].copy_from_slice(seed.get(1..32).unwrap());
    padded[32..].copy_from_slice(seed.get(32..).unwrap());

    let (padded_nullifier, padded_viewing) = expand_roles(&padded, Curve::Ed25519).unwrap();
    let padded_owner_hash = hash::owner_hash(
        &software.signing_pubkey(),
        &padded_nullifier.pubkey().unwrap(),
    )
    .unwrap();

    assert_ne!(padded_owner_hash, software.owner_hash().unwrap());
    assert_ne!(padded_viewing.pubkey(), software.viewing_pubkey());
}

/// A seed signed by another key must never be expanded: it would yield a
/// well-formed identity that is not the user's.
#[tokio::test]
async fn ed25519_bootstrap_rejects_a_foreign_seed_signature() {
    let mock = Arc::new(
        MockTurnkey::ed25519(&ED25519_SECRET).with_behavior(Behavior::ForeignSeedSignature),
    );

    assert!(matches!(
        bootstrap_ed25519(mock).await,
        Err(TurnkeyKeypairError::SeedSignatureInvalid)
    ));
}

#[tokio::test]
async fn ed25519_bootstrap_rejects_a_non_ed25519_key() {
    let mock =
        Arc::new(MockTurnkey::ed25519(&ED25519_SECRET).with_reported_curve(TurnkeyCurve::P256));

    assert!(matches!(
        bootstrap_ed25519(mock).await,
        Err(TurnkeyKeypairError::CurveMismatch {
            expected: TurnkeyCurve::Ed25519,
            actual: TurnkeyCurve::P256,
            ..
        })
    ));
}

#[tokio::test]
async fn ed25519_bootstrap_rejects_a_malformed_public_key() {
    let mock =
        Arc::new(MockTurnkey::ed25519(&ED25519_SECRET).with_reported_public_key(vec![7u8; 31]));

    assert!(matches!(
        bootstrap_ed25519(mock).await,
        Err(TurnkeyKeypairError::MalformedResponse { .. })
    ));
}

/// A backend whose key becomes unusable still serves the identity it already
/// derived; only signing fails, and it fails as `SigningFailed`.
#[tokio::test]
async fn ed25519_sign_failure_surfaces_as_signing_failed() {
    let mock =
        Arc::new(MockTurnkey::ed25519(&ED25519_SECRET).with_behavior(Behavior::FailAfterBootstrap));
    let turnkey = bootstrap_ed25519(mock).await.unwrap();

    assert_eq!(
        turnkey.owner_hash().unwrap(),
        software_ed25519().owner_hash().unwrap()
    );
    assert!(matches!(
        turnkey.sign_message_async(b"benign message").await,
        Err(TurnkeyKeypairError::Transport(_))
    ));
    assert_eq!(
        ShieldedKeypairTrait::sign_message(&turnkey, b"benign message"),
        Err(KeypairError::SigningFailed)
    );
}

/// The integration hazard the blocking bridge exists for: the synchronous trait
/// method called directly on a multi-thread runtime worker, which is where a
/// wallet service calls from. `Runtime::block_on` would panic here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ed25519_sync_trait_method_works_on_a_runtime_worker() {
    let turnkey = bootstrap_ed25519(Arc::new(MockTurnkey::ed25519(&ED25519_SECRET)))
        .await
        .unwrap();
    let software = software_ed25519();

    let msg = b"signed from inside a runtime";
    assert_eq!(
        ShieldedKeypairTrait::sign_message(&turnkey, msg).unwrap(),
        software.sign_message(msg).unwrap()
    );
}

// --- P-256 rail -------------------------------------------------------------

/// The signing key is remote and the roles are supplied, so the identity is the
/// composition of the two — checked against both sources independently.
#[tokio::test]
async fn p256_backend_composes_remote_signing_key_with_supplied_roles() {
    let mock = Arc::new(MockTurnkey::p256(&P256_SIGN_SECRET));
    let turnkey = bootstrap_p256(mock.clone()).await.unwrap();

    let software_signing = SigningKey::from_p256_bytes(&P256_SIGN_SECRET).unwrap();
    let (nullifier_key, viewing_key) = supplied_roles();

    assert_eq!(turnkey.signing_pubkey(), software_signing.pubkey());
    assert_eq!(turnkey.viewing_pubkey(), viewing_key.pubkey());
    assert_eq!(turnkey.curve(), Curve::P256);
    assert_eq!(
        turnkey.nullifier_pubkey().unwrap(),
        nullifier_key.pubkey().unwrap()
    );

    let expected_owner_hash =
        hash::owner_hash(&software_signing.pubkey(), &nullifier_key.pubkey().unwrap()).unwrap();
    assert_eq!(turnkey.owner_hash().unwrap(), expected_owner_hash);
    assert_eq!(
        turnkey.compressed_address().unwrap().owner_hash,
        expected_owner_hash
    );

    // Reading the key does not sign anything.
    assert_eq!(mock.get_private_key_calls.load(Ordering::SeqCst), 1);
    assert_eq!(mock.sign_calls.load(Ordering::SeqCst), 0);
}

/// Prehash signing with `NO_OP`, low-S, verifying against the published key.
#[tokio::test]
async fn p256_backend_signs_prehash_with_no_op() {
    let mock = Arc::new(MockTurnkey::p256(&P256_SIGN_SECRET));
    let turnkey = bootstrap_p256(mock.clone()).await.unwrap();
    let software_signing = SigningKey::from_p256_bytes(&P256_SIGN_SECRET).unwrap();

    let digest = hash::sha256(b"private tx hash binding");
    let signature = turnkey.sign_hash_async(&digest).await.unwrap();

    assert_eq!(signature, software_signing.sign_hash(&digest).unwrap());
    assert!(EcdsaSignature::from_slice(&signature)
        .unwrap()
        .normalize_s()
        .is_none());
    assert!(turnkey.signing_pubkey().verify_hash(&digest, &signature));
    assert_eq!(mock.hash_functions(), vec![PayloadHashFunction::NoOp]);

    // Deterministic ECDSA: the same digest signs identically through the trait.
    assert_eq!(
        ShieldedKeypairTrait::sign_hash(&turnkey, &digest).unwrap(),
        signature
    );
}

/// A high-S device signature is normalized before it reaches the caller, because
/// both the SPP proof and the secp256r1 precompile reject high-S.
#[tokio::test]
async fn p256_backend_normalizes_high_s() {
    let mock = Arc::new(MockTurnkey::p256(&P256_SIGN_SECRET).with_behavior(Behavior::HighS));
    let turnkey = bootstrap_p256(mock).await.unwrap();
    let software_signing = SigningKey::from_p256_bytes(&P256_SIGN_SECRET).unwrap();

    let digest = hash::sha256(b"high-s device signature");
    let signature = turnkey.sign_hash_async(&digest).await.unwrap();

    assert!(EcdsaSignature::from_slice(&signature)
        .unwrap()
        .normalize_s()
        .is_none());
    assert!(turnkey.signing_pubkey().verify_hash(&digest, &signature));
    // Normalization is what makes a high-S device indistinguishable from the
    // software key, which is the guarantee `sign_hash` documents.
    assert_eq!(signature, software_signing.sign_hash(&digest).unwrap());
}

/// `sign_message_async` hashes with SHA-256 first, matching what Solana's
/// secp256r1 precompile verifies and what `SigningKey::sign_message` does on this rail.
#[tokio::test]
async fn p256_backend_signs_a_message_as_sha256_prehash() {
    let mock = Arc::new(MockTurnkey::p256(&P256_SIGN_SECRET));
    let turnkey = bootstrap_p256(mock.clone()).await.unwrap();
    let software_signing = SigningKey::from_p256_bytes(&P256_SIGN_SECRET).unwrap();

    let message = b"registry binding";
    let signature = turnkey.sign_message_async(message).await.unwrap();

    assert_eq!(signature, software_signing.sign_message(message).unwrap());
    assert_eq!(mock.signed_payloads(), vec![hash::sha256(message).to_vec()]);
}

/// Anything that is not a 32-byte prehash is refused, rather than hashed into
/// something the proof does not commit to.
#[tokio::test]
async fn p256_backend_rejects_payloads_that_are_not_a_prehash() {
    let mock = Arc::new(MockTurnkey::p256(&P256_SIGN_SECRET));
    let turnkey = bootstrap_p256(mock.clone()).await.unwrap();

    let mut prefixed = [0u8; 32];
    prefixed[..DERIVATION_PAYLOAD_PREFIX.len()].copy_from_slice(DERIVATION_PAYLOAD_PREFIX);
    assert!(matches!(
        turnkey.sign_hash_async(&prefixed).await,
        Err(TurnkeyKeypairError::Keypair(KeypairError::DerivationInput))
    ));
    assert_eq!(
        ShieldedKeypairTrait::sign_hash(&turnkey, &prefixed),
        Err(KeypairError::DerivationInput)
    );
    assert!(matches!(
        turnkey.sign_message_async(ED25519_DERIVATION_MSG).await,
        Err(TurnkeyKeypairError::Keypair(KeypairError::DerivationInput))
    ));
    assert_eq!(mock.sign_calls.load(Ordering::SeqCst), 0);
}

/// Turnkey may report either SEC1 encoding; both normalize to the compressed
/// form a shielded `PublicKey` carries.
#[tokio::test]
async fn p256_bootstrap_accepts_an_uncompressed_public_key() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = p256::SecretKey::from_slice(&P256_SIGN_SECRET).unwrap();
    let uncompressed = secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    assert_eq!(uncompressed.len(), 65);

    let mock =
        Arc::new(MockTurnkey::p256(&P256_SIGN_SECRET).with_reported_public_key(uncompressed));
    let turnkey = bootstrap_p256(mock).await.unwrap();

    assert_eq!(
        turnkey.signing_pubkey(),
        SigningKey::from_p256_bytes(&P256_SIGN_SECRET)
            .unwrap()
            .pubkey()
    );
}

#[tokio::test]
async fn p256_bootstrap_rejects_a_non_p256_key() {
    let mock =
        Arc::new(MockTurnkey::p256(&P256_SIGN_SECRET).with_reported_curve(TurnkeyCurve::Other));

    assert!(matches!(
        bootstrap_p256(mock).await,
        Err(TurnkeyKeypairError::CurveMismatch {
            expected: TurnkeyCurve::P256,
            actual: TurnkeyCurve::Other,
            ..
        })
    ));
}
