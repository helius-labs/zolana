//! Live acceptance test against the real Turnkey API.
//!
//! `#[ignore]`d, so `cargo test` never reaches it. It refuses to start without a
//! dedicated-organization acknowledgement and its own `TURNKEY_TEST_*`
//! credentials, distinct from any runtime variables, because it creates real
//! sub-organizations and private keys:
//!
//! ```bash
//! export TURNKEY_LIVE_TEST_ACKNOWLEDGE_DEDICATED_ORG=I_UNDERSTAND_THIS_MUST_USE_A_DEDICATED_TURNKEY_TEST_ORGANIZATION
//! export TURNKEY_TEST_ORGANIZATION_ID=...
//! export TURNKEY_TEST_API_PUBLIC_KEY=...
//! export TURNKEY_TEST_API_PRIVATE_KEY=...
//! cargo test -p zolana-keypair-turnkey --test live -- --ignored --nocapture
//! ```
//!
//! # What only a live run can establish
//!
//! The offline suite pins every backend against a software keypair, but it
//! cannot check what the provider actually does. Three things here can only be
//! learned from Turnkey itself:
//!
//! 1. **`r`/`s` are full width.** The ed25519 rail refuses to re-pad a short
//!    component, because on the derivation path a padded seed is a different
//!    wallet. Turnkey's own `@turnkey/solana` concatenates the two hex strings
//!    with no length check, so full width is the provider's assumption too — but
//!    it is undocumented. Bootstrap succeeding *is* the check.
//! 2. **Ed25519 signing is deterministic.** The whole recovery story rests on
//!    it: re-derive the same seed, get the same wallet. RFC 8032 fixes the
//!    nonce, but nothing forces a remote signer to comply. Two bootstraps of one
//!    key must produce one identity.
//! 3. **Whether P-256 ECDSA is deterministic.** Undocumented, and it decides
//!    whether the P-256 rail could ever derive its roles from a signature
//!    instead of the ECDH that Turnkey cannot perform. Reported, not asserted: a
//!    random nonce is a legitimate provider choice, not a failure of this code.
//!
//! Provisioning lives here rather than in the crate. Creating and deleting
//! sub-organizations is organization lifecycle, not shielded-keypair behaviour,
//! and only this test needs it.

#![cfg(feature = "api")]

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use turnkey_client::{
    generated::immutable::{
        activity::v1::{
            ApiKeyParamsV2, CreatePrivateKeysIntentV2, CreateSubOrganizationIntentV8,
            DeleteSubOrganizationIntent, PrivateKeyParams, RootUserParamsV5,
        },
        common::v1::{AddressFormat, ApiKeyCurve, Curve as ApiCurve},
    },
    TurnkeyClient, TurnkeyP256ApiKey,
};
use zolana_keypair::{
    derivation::{ed25519_derivation_message, ED25519_DERIVATION_MSG},
    Curve, KeypairError, NullifierKey, ShieldedKeypairTrait, ViewingKey,
};
use zolana_keypair_turnkey::{
    TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef, TurnkeyKeypairError,
    TurnkeyP256ShieldedKeypair,
};

const ACKNOWLEDGEMENT: &str = "I_UNDERSTAND_THIS_MUST_USE_A_DEDICATED_TURNKEY_TEST_ORGANIZATION";

/// Names every child with this prefix so anything a killed run leaves behind is
/// discoverable in the test organization.
const LABEL_PREFIX: &str = "zolana-keypair-turnkey-live";

type Client = TurnkeyClient<TurnkeyP256ApiKey>;

struct Harness {
    client: Arc<Client>,
    /// Child organization created by this run, deleted on drop.
    sub_organization_id: String,
    ed25519: TurnkeyKeyRef,
    p256: TurnkeyKeyRef,
    /// The Solana address Turnkey reported when it created the ed25519 key.
    solana_address: String,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis())
}

/// Reads the guard variables, or returns `None` so the test skips loudly rather
/// than failing when someone runs `--ignored` without credentials.
fn guarded_client() -> Option<(Arc<Client>, String, String)> {
    let acknowledgement = std::env::var("TURNKEY_LIVE_TEST_ACKNOWLEDGE_DEDICATED_ORG").ok()?;
    assert_eq!(
        acknowledgement, ACKNOWLEDGEMENT,
        "the acknowledgement must match exactly; this test creates real Turnkey resources"
    );
    let organization_id = std::env::var("TURNKEY_TEST_ORGANIZATION_ID").ok()?;
    let public_key = std::env::var("TURNKEY_TEST_API_PUBLIC_KEY").ok()?;
    let private_key = std::env::var("TURNKEY_TEST_API_PRIVATE_KEY").ok()?;
    let base_url = std::env::var("TURNKEY_TEST_BASE_URL")
        .unwrap_or_else(|_| "https://api.turnkey.com".to_string());

    let api_key = TurnkeyP256ApiKey::from_strings(private_key, Some(public_key))
        .expect("TURNKEY_TEST_API_PRIVATE_KEY is a valid P-256 key");
    let root_public_key = hex::encode(api_key.compressed_public_key());
    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(base_url)
        .build()
        .expect("client builds");
    Some((Arc::new(client), organization_id, root_public_key))
}

impl Harness {
    /// Creates one child organization holding one ed25519 and one P-256 key.
    ///
    /// The test credential is installed as a threshold-one root in the child so
    /// the same key can stamp the child's activities and delete it afterwards.
    /// That is a test-fixture shape, not a custody recommendation.
    async fn provision() -> Option<Self> {
        let (client, parent, root_public_key) = guarded_client()?;
        let label = format!("{LABEL_PREFIX}-{}", now_ms());

        let created = client
            .create_sub_organization(
                parent,
                now_ms(),
                CreateSubOrganizationIntentV8 {
                    sub_organization_name: label.clone(),
                    root_users: vec![RootUserParamsV5 {
                        user_name: "zolana-keypair-turnkey-live".to_string(),
                        user_email: None,
                        user_phone_number: None,
                        api_keys: vec![ApiKeyParamsV2 {
                            api_key_name: "zolana-keypair-turnkey-live".to_string(),
                            public_key: root_public_key,
                            curve_type: ApiKeyCurve::P256,
                            expiration_seconds: None,
                        }],
                        authenticators: Vec::new(),
                        oauth_providers: Vec::new(),
                    }],
                    root_quorum_threshold: 1,
                    wallet: None,
                    disable_email_recovery: Some(true),
                    disable_email_auth: Some(true),
                    disable_sms_auth: Some(true),
                    disable_otp_email_auth: Some(true),
                    verification_token: None,
                    client_signature: None,
                },
            )
            .await
            .expect("create_sub_organization succeeds");
        let sub_organization_id = created.result.sub_organization_id;
        assert!(
            !sub_organization_id.trim().is_empty(),
            "Turnkey returned an empty sub-organization id"
        );

        // Recorded before anything else can fail, so a later error still leaves
        // a child this run knows how to delete.
        let mut harness = Self {
            client,
            sub_organization_id: sub_organization_id.clone(),
            ed25519: TurnkeyKeyRef::new(&sub_organization_id, ""),
            p256: TurnkeyKeyRef::new(&sub_organization_id, ""),
            solana_address: String::new(),
        };

        let keys = harness
            .client
            .create_private_keys(
                sub_organization_id.clone(),
                now_ms(),
                CreatePrivateKeysIntentV2 {
                    private_keys: vec![
                        PrivateKeyParams {
                            private_key_name: "shielded-owner-ed25519".to_string(),
                            curve: ApiCurve::Ed25519,
                            private_key_tags: Vec::new(),
                            address_formats: vec![AddressFormat::Solana],
                        },
                        PrivateKeyParams {
                            private_key_name: "shielded-owner-p256".to_string(),
                            curve: ApiCurve::P256,
                            private_key_tags: Vec::new(),
                            address_formats: vec![AddressFormat::Compressed],
                        },
                    ],
                },
            )
            .await
            .expect("create_private_keys succeeds")
            .result
            .private_keys;
        assert_eq!(keys.len(), 2, "expected exactly two keys");

        // Selected by returned address format, never by response order.
        let ed25519 = keys
            .iter()
            .find(|key| {
                key.addresses
                    .iter()
                    .any(|address| address.format == AddressFormat::Solana)
            })
            .expect("one key reports a Solana address");
        let p256 = keys
            .iter()
            .find(|key| {
                key.addresses
                    .iter()
                    .any(|address| address.format == AddressFormat::Compressed)
            })
            .expect("one key reports a compressed address");
        assert_ne!(
            ed25519.private_key_id, p256.private_key_id,
            "Turnkey returned one key for both roles"
        );

        harness.solana_address = ed25519
            .addresses
            .iter()
            .find(|address| address.format == AddressFormat::Solana)
            .expect("Solana address present")
            .address
            .clone();
        harness.ed25519 = TurnkeyKeyRef::new(&sub_organization_id, ed25519.private_key_id.clone());
        harness.p256 = TurnkeyKeyRef::new(&sub_organization_id, p256.private_key_id.clone());
        Some(harness)
    }

    fn activities(&self) -> Arc<TurnkeyApiActivities<TurnkeyP256ApiKey>> {
        Arc::new(TurnkeyApiActivities::new(Arc::clone(&self.client)))
    }

    /// Best effort, retried: an undeleted child is discoverable by its label
    /// prefix, but leaving one behind is still a failure worth reporting.
    async fn teardown(&self) {
        const ATTEMPTS: usize = 3;
        for attempt in 0..ATTEMPTS {
            let deleted = self
                .client
                .delete_sub_organization(
                    self.sub_organization_id.clone(),
                    now_ms(),
                    DeleteSubOrganizationIntent {
                        delete_without_export: Some(true),
                    },
                )
                .await;
            match deleted {
                Ok(result) if result.result.sub_organization_uuid == self.sub_organization_id => {
                    return
                }
                Ok(result) => panic!(
                    "delete returned sub-organization `{}`, expected `{}`",
                    result.result.sub_organization_uuid, self.sub_organization_id
                ),
                Err(error) if attempt + 1 == ATTEMPTS => panic!(
                    "could not delete sub-organization `{}` after {ATTEMPTS} attempts: {error}. \
                     Delete it from a child root context with deleteWithoutExport=true.",
                    self.sub_organization_id
                ),
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
                }
            }
        }
    }
}

/// One test, because every assertion shares one provisioned child and teardown
/// has to run even when an assertion fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "creates real Turnkey resources; see the module docs"]
async fn live_turnkey_backends_behave_like_the_offline_suite() {
    let Some(harness) = Harness::provision().await else {
        eprintln!(
            "SKIPPED: set TURNKEY_LIVE_TEST_ACKNOWLEDGE_DEDICATED_ORG and the TURNKEY_TEST_* \
             credentials to run this against a dedicated test organization"
        );
        return;
    };

    // Run the body in a task so an assertion failure is captured and teardown
    // still happens before the test reports it.
    let body = {
        let activities = harness.activities();
        let ed25519 = harness.ed25519.clone();
        let p256 = harness.p256.clone();
        let solana_address = harness.solana_address.clone();
        tokio::spawn(async move { exercise(activities, ed25519, p256, solana_address).await }).await
    };
    harness.teardown().await;
    body.expect("live body did not panic");
}

async fn exercise(
    activities: Arc<TurnkeyApiActivities<TurnkeyP256ApiKey>>,
    ed25519: TurnkeyKeyRef,
    p256: TurnkeyKeyRef,
    solana_address: String,
) {
    // --- ed25519 rail --------------------------------------------------------

    // Bootstrap succeeding is the live check on full-width r/s: a short
    // component is refused outright, and a wrong-width seed cannot expand.
    let wallet = TurnkeyEd25519ShieldedKeypair::bootstrap(activities.clone(), ed25519.clone())
        .await
        .expect("ed25519 bootstrap succeeds against the live API");

    assert_eq!(wallet.curve(), Curve::Ed25519);
    assert_eq!(
        wallet.solana_address().to_string(),
        solana_address,
        "derived Solana address disagrees with the one Turnkey reported at creation"
    );
    let address = wallet.shielded_address().expect("shielded address derives");
    assert_eq!(
        address.signing_pubkey,
        wallet.signing_pubkey(),
        "published address does not carry the remote signing key"
    );

    // Determinism: the recovery story is that these two IDs plus a credential
    // rebuild the wallet. That holds only if Turnkey's ed25519 signature over
    // the derivation envelope is reproducible.
    let again = TurnkeyEd25519ShieldedKeypair::bootstrap(activities.clone(), ed25519.clone())
        .await
        .expect("second ed25519 bootstrap succeeds");
    assert_eq!(
        wallet.owner_hash().expect("owner hash"),
        again.owner_hash().expect("owner hash"),
        "Turnkey's ed25519 signing is not deterministic, so this wallet is not recoverable"
    );
    assert_eq!(
        wallet.viewing_pubkey(),
        again.viewing_pubkey(),
        "viewing key differs between bootstraps"
    );

    // A remote signature verifies against the published key.
    let message = b"zolana-keypair-turnkey live message";
    let signature = wallet
        .sign_message_async(message)
        .await
        .expect("remote ed25519 signature");
    assert!(
        wallet.signing_pubkey().verify_message(message, &signature),
        "remote signature does not verify against the reported public key"
    );

    // The seed guard is local, so neither form reaches Turnkey.
    let signer = wallet.signing_pubkey().as_ed25519().expect("ed25519 owner");
    for guarded in [
        ED25519_DERIVATION_MSG.to_vec(),
        ed25519_derivation_message(&signer),
    ] {
        assert!(matches!(
            wallet.sign_message_async(&guarded).await,
            Err(TurnkeyKeypairError::Keypair(KeypairError::DerivationInput))
        ));
    }
    assert_eq!(
        ShieldedKeypairTrait::sign_hash(&wallet, &[7u8; 32]),
        Err(KeypairError::NotP256),
        "the ed25519 rail must not produce an ECDSA-over-digest signature"
    );

    // --- P-256 rail ----------------------------------------------------------

    // Turnkey cannot produce this rail's seed, so the roles are supplied. Fixed
    // values keep the run reproducible; they are throwaway test material.
    let spend = TurnkeyP256ShieldedKeypair::bootstrap_with_roles(
        activities.clone(),
        p256.clone(),
        NullifierKey::from_secret([23u8; 31]),
        ViewingKey::from_bytes(&[22u8; 32]).expect("viewing key"),
    )
    .await
    .expect("P-256 bootstrap succeeds");

    assert_eq!(spend.curve(), Curve::P256);
    let digest = zolana_keypair::hash::sha256(b"private tx hash binding");
    let first = spend
        .sign_hash_async(&digest)
        .await
        .expect("remote P-256 prehash signature");
    assert!(
        spend.signing_pubkey().verify_hash(&digest, &first),
        "remote P-256 signature does not verify against the reported public key"
    );
    assert!(
        p256::ecdsa::Signature::from_slice(&first)
            .expect("compact signature")
            .normalize_s()
            .is_none(),
        "signature is not low-S after normalization"
    );

    // Diagnostic, not an assertion. A deterministic answer here (RFC 6979) is
    // what would let the P-256 rail derive its roles from a signature instead of
    // the ECDH Turnkey cannot perform. A random nonce is a legitimate provider
    // choice, so report it and move on.
    let second = spend
        .sign_hash_async(&digest)
        .await
        .expect("second remote P-256 signature");
    if first == second {
        println!(
            "DIAGNOSTIC: Turnkey P-256 ECDSA appears deterministic (RFC 6979) — a \
             signature-derived seed for the P-256 rail may be viable."
        );
    } else {
        println!(
            "DIAGNOSTIC: Turnkey P-256 ECDSA is NOT deterministic — the P-256 rail cannot root \
             itself from a signature, and ECDH remains the only option."
        );
    }

    // Message form is SHA-256 then the same digest path.
    let message_signature = spend
        .sign_message_async(message)
        .await
        .expect("remote P-256 message signature");
    assert!(
        spend
            .signing_pubkey()
            .verify_message(message, &message_signature),
        "P-256 message signature does not verify as ECDSA over SHA-256(message)"
    );
}
