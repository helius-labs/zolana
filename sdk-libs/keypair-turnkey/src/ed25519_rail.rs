//! The ed25519 rail: a Turnkey key that roots a whole shielded identity.
//!
//! On this rail the derivation seed is a deterministic RFC 8032 signature over a
//! fixed message ([`derivation::ed25519_derivation_message`]), which Turnkey can
//! produce. So one `SIGN_RAW_PAYLOAD_V2` at bootstrap yields the seed, and the
//! nullifier and viewing secrets expand from it exactly as they would for a
//! software keypair. The signing key never leaves Turnkey, and nothing secret
//! needs to be persisted: [`TurnkeyKeyRef`] plus a Turnkey credential rebuilds
//! the identity.
//!
//! # What this does and does not isolate
//!
//! Turnkey holds the spend key, enforces policy on its use, and keeps it
//! available across host loss. It is **not** a privacy boundary. The seed is a
//! signature that key can always produce, so anyone authorized to call
//! `SIGN_RAW_PAYLOAD` on it can re-derive the viewing and nullifier secrets and
//! obtain both full view and full spend. [`ShieldedKeypairTrait::sign_message`]
//! refuses derivation-shaped payloads, but that guard is host-side only and
//! constrains
//! this process, not the credential. Narrowing it requires a Turnkey policy that
//! denies the derivation payload once bootstrap is done.
//!
//! # Approval-gated keys
//!
//! A quorum policy makes signing asynchronous: Turnkey holds the activity for
//! approvers instead of completing it. That surfaces as
//! [`TurnkeyKeypairError::RequiresApproval`], and a still-pending activity as
//! [`TurnkeyKeypairError::StillPending`] — which is not proof of failure, so a
//! caller that retries it blindly can double-submit.
//!
//! Both are only visible on the `async` methods. `KeypairError` has no variant
//! for either, so [`ShieldedKeypairTrait`]'s synchronous methods can only report
//! `SigningFailed`. Use the async twin whenever the key may be approval-gated.

use std::{fmt, sync::Arc};

use ed25519_dalek::VerifyingKey;
use solana_address::Address;
use zolana_keypair::{
    derivation, hash,
    shielded::{CompressedShieldedAddress, ShieldedAddress},
    Curve, KeypairError, NullifierKey, P256Pubkey, PublicKey, ShieldedKeypairTrait, ViewingKey,
};

use crate::{
    activities::{PayloadHashFunction, TurnkeyActivities, TurnkeyCurve, TurnkeyKeyRef},
    blocking::Executor,
    codec,
    error::TurnkeyKeypairError,
};

const ED25519_PUBKEY_LEN: usize = 32;

/// A shielded identity whose signing key lives in a Turnkey sub-organization.
///
/// The viewing and nullifier secrets are held in this process, as the
/// [`ShieldedKeypairTrait`] custody boundary requires — both are private proof
/// inputs, so no signing device can hold them for us.
pub struct TurnkeyEd25519ShieldedKeypair {
    activities: Arc<dyn TurnkeyActivities>,
    executor: Executor,
    key_ref: TurnkeyKeyRef,
    ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    signing_pubkey: PublicKey,
    nullifier_key: NullifierKey,
    viewing_key: ViewingKey,
}

impl TurnkeyEd25519ShieldedKeypair {
    /// Reads the key's public half from Turnkey, then bootstraps from it.
    ///
    /// Two round trips. Prefer [`Self::bootstrap_with_pubkey`] when the caller
    /// already learned the public key from provisioning.
    pub async fn bootstrap(
        activities: Arc<dyn TurnkeyActivities>,
        key_ref: TurnkeyKeyRef,
    ) -> Result<Self, TurnkeyKeypairError> {
        let remote = activities
            .get_private_key(&key_ref.organization_id, &key_ref.private_key_id)
            .await?;
        if remote.curve != TurnkeyCurve::Ed25519 {
            return Err(TurnkeyKeypairError::CurveMismatch {
                key_id: key_ref.private_key_id.clone(),
                expected: TurnkeyCurve::Ed25519,
                actual: remote.curve,
            });
        }
        let ed25519_pubkey: [u8; ED25519_PUBKEY_LEN] =
            remote.public_key.as_slice().try_into().map_err(|_| {
                TurnkeyKeypairError::malformed(
                    "ed25519 public key",
                    format!(
                        "{} bytes, expected {ED25519_PUBKEY_LEN}",
                        remote.public_key.len()
                    ),
                )
            })?;
        Self::bootstrap_with_pubkey(activities, key_ref, ed25519_pubkey).await
    }

    /// Bootstraps against a public key the caller already has.
    ///
    /// The seed signature is still verified against `ed25519_pubkey`, so this is
    /// not a weaker path: it proves Turnkey holds the key the caller named. A
    /// mismatch fails with [`TurnkeyKeypairError::SeedSignatureInvalid`] instead
    /// of deriving a wrong-but-plausible identity.
    pub async fn bootstrap_with_pubkey(
        activities: Arc<dyn TurnkeyActivities>,
        key_ref: TurnkeyKeyRef,
        ed25519_pubkey: [u8; ED25519_PUBKEY_LEN],
    ) -> Result<Self, TurnkeyKeypairError> {
        // Validated here so a point that is not on the curve is a malformed
        // response rather than an unexplained verification failure below.
        VerifyingKey::from_bytes(&ed25519_pubkey).map_err(|error| {
            TurnkeyKeypairError::malformed("ed25519 public key", error.to_string())
        })?;
        let signing_pubkey = PublicKey::from_ed25519(&ed25519_pubkey);

        // The one call that is *allowed* to sign a derivation payload. Every
        // later `sign_message` refuses it.
        let envelope = derivation::ed25519_derivation_message(&ed25519_pubkey);
        let raw = activities
            .sign_raw_payload(
                &key_ref.organization_id,
                &key_ref.private_key_id,
                &envelope,
                PayloadHashFunction::NotApplicable,
            )
            .await?;
        let seed = codec::ed25519_signature(&raw)?;
        if !signing_pubkey.verify_message(&envelope, &seed) {
            return Err(TurnkeyKeypairError::SeedSignatureInvalid);
        }

        let (nullifier_key, viewing_key) = derivation::expand_roles(&seed, Curve::Ed25519)?;

        Ok(Self {
            activities,
            executor: Executor::new()?,
            key_ref,
            ed25519_pubkey,
            signing_pubkey,
            nullifier_key,
            viewing_key,
        })
    }

    /// The non-secret state that reproduces this identity.
    pub fn key_ref(&self) -> &TurnkeyKeyRef {
        &self.key_ref
    }

    /// The Solana address of the same key. On this rail it is both the wallet's
    /// owner-signer and, in the reference service, the fee payer.
    pub fn solana_address(&self) -> Address {
        Address::new_from_array(self.ed25519_pubkey)
    }

    /// The derived viewing key, for a wallet scan that needs the key itself
    /// rather than the [`zolana_keypair::ViewingKeyTrait`] operations.
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// Signs through Turnkey without the blocking bridge. Prefer this whenever
    /// the caller is already async; [`ShieldedKeypairTrait::sign_message`]
    /// exists for callers that are not.
    pub async fn sign_message_async(
        &self,
        message: &[u8],
    ) -> Result<[u8; 64], TurnkeyKeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput.into());
        }
        self.sign_unguarded(message).await
    }

    async fn sign_unguarded(&self, msg: &[u8]) -> Result<[u8; 64], TurnkeyKeypairError> {
        let raw = self
            .activities
            .sign_raw_payload(
                &self.key_ref.organization_id,
                &self.key_ref.private_key_id,
                msg,
                PayloadHashFunction::NotApplicable,
            )
            .await?;
        let signature = codec::ed25519_signature(&raw)?;
        if !self.signing_pubkey.verify_message(msg, &signature) {
            return Err(TurnkeyKeypairError::SignatureKeyMismatch {
                key_id: self.key_ref.private_key_id.clone(),
            });
        }
        Ok(signature)
    }
}

/// Hand-written so the derived role secrets cannot reach a log. Only the remote
/// reference and public halves are printed.
impl fmt::Debug for TurnkeyEd25519ShieldedKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnkeyEd25519ShieldedKeypair")
            .field("key_ref", &self.key_ref)
            .field("ed25519_pubkey", &hex::encode(self.ed25519_pubkey))
            .field(
                "viewing_pubkey",
                &hex::encode(self.viewing_key.pubkey().as_bytes()),
            )
            .field("nullifier_key", &"<redacted>")
            .finish()
    }
}

impl ShieldedKeypairTrait for TurnkeyEd25519ShieldedKeypair {
    fn signing_pubkey(&self) -> PublicKey {
        self.signing_pubkey
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_key.pubkey()
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError> {
        Ok(ShieldedAddress {
            signing_pubkey: self.signing_pubkey,
            nullifier_pubkey: self.nullifier_key.pubkey()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        hash::owner_hash(&self.signing_pubkey, &self.nullifier_key.pubkey()?)
    }

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError> {
        Ok(CompressedShieldedAddress {
            owner_hash: self.owner_hash()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    /// Refuses any payload that would reproduce the derivation seed, so a
    /// caller cannot walk this handle back to the role secrets. Enforced here,
    /// in this process — see the module docs for what that does not cover.
    fn sign_message(&self, msg: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(msg) {
            return Err(KeypairError::DerivationInput);
        }
        let activities = Arc::clone(&self.activities);
        let key_ref = self.key_ref.clone();
        let payload = msg.to_vec();
        let signing_pubkey = self.signing_pubkey;

        self.executor
            .block_on(async move {
                let raw = activities
                    .sign_raw_payload(
                        &key_ref.organization_id,
                        &key_ref.private_key_id,
                        &payload,
                        PayloadHashFunction::NotApplicable,
                    )
                    .await?;
                let signature = codec::ed25519_signature(&raw)?;
                if !signing_pubkey.verify_message(&payload, &signature) {
                    return Err(TurnkeyKeypairError::SignatureKeyMismatch {
                        key_id: key_ref.private_key_id.clone(),
                    });
                }
                Ok(signature)
            })
            .map_err(|_| KeypairError::SigningFailed)
    }

    /// An ed25519 owner has no ECDSA-over-digest signature. It authorizes a
    /// spend by signing the Solana transaction, so the proof path never asks
    /// this rail for one; a digest to be signed goes through
    /// [`Self::sign_message`] as raw bytes.
    fn sign_hash(&self, _hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        Err(KeypairError::NotP256)
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], KeypairError> {
        self.nullifier_key.nullifier(utxo_hash, blinding)
    }

    fn nullifier_key(&self) -> NullifierKey {
        self.nullifier_key.clone()
    }
}

// Forwards to the derived viewing key. Turnkey exposes no key agreement, so
// these operations are necessarily local; the viewing secret is host-side by
// the trait's own custody rule.
zolana_keypair::forward_viewing_key_trait!(TurnkeyEd25519ShieldedKeypair => viewing_key);
