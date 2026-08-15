//! The P-256 rail: Turnkey can sign for it, but cannot root it.
//!
//! A P-256 shielded owner derives both role secrets from
//! `ECDH(signing_sk, P_derive)`. Turnkey exposes no key-agreement activity of
//! any kind — signing and transaction signing are the only cryptographic
//! operations in its API — so that seed is unobtainable, and no amount of
//! wrapping changes it. Exporting the key would produce the seed and destroy the
//! reason for using Turnkey at all.
//!
//! So this backend takes the two role secrets from the caller and uses Turnkey
//! only as the spend-signing device. That is a real split-custody design (it is
//! what AWS KMS's three-key backend does, with `DeriveSharedSecret` supplying
//! the roots), but it comes with a consequence the ed25519 rail does not have:
//! **the roots are not recoverable from the signing key**, so whoever holds them
//! must persist them. Losing them loses the wallet even though Turnkey still
//! holds the spend key.
//!
//! Prefer [`crate::TurnkeyEd25519ShieldedKeypair`] unless the P-256 owner rail
//! is specifically required.
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

/// A shielded identity whose P-256 spend key lives in Turnkey and whose role
/// secrets were supplied by the caller.
pub struct TurnkeyP256ShieldedKeypair {
    activities: Arc<dyn TurnkeyActivities>,
    executor: Executor,
    key_ref: TurnkeyKeyRef,
    p256_pubkey: P256Pubkey,
    signing_pubkey: PublicKey,
    nullifier_key: NullifierKey,
    viewing_key: ViewingKey,
}

impl TurnkeyP256ShieldedKeypair {
    /// Binds a Turnkey P-256 signing key to caller-supplied role secrets.
    ///
    /// There is deliberately no constructor that derives the roles: on this rail
    /// that would require a seed Turnkey cannot produce, and any locally invented
    /// substitute would be unrecoverable material masquerading as derived
    /// material. See the module docs.
    pub async fn bootstrap_with_roles(
        activities: Arc<dyn TurnkeyActivities>,
        key_ref: TurnkeyKeyRef,
        nullifier_key: NullifierKey,
        viewing_key: ViewingKey,
    ) -> Result<Self, TurnkeyKeypairError> {
        let remote = activities
            .get_private_key(&key_ref.organization_id, &key_ref.private_key_id)
            .await?;
        if remote.curve != TurnkeyCurve::P256 {
            return Err(TurnkeyKeypairError::CurveMismatch {
                key_id: key_ref.private_key_id.clone(),
                expected: TurnkeyCurve::P256,
                actual: remote.curve,
            });
        }
        let p256_pubkey = compressed_pubkey(&remote.public_key)?;

        Ok(Self {
            activities,
            executor: Executor::new()?,
            key_ref,
            p256_pubkey,
            signing_pubkey: PublicKey::from_p256(&p256_pubkey),
            nullifier_key,
            viewing_key,
        })
    }

    pub fn key_ref(&self) -> &TurnkeyKeyRef {
        &self.key_ref
    }

    pub fn p256_pubkey(&self) -> P256Pubkey {
        self.p256_pubkey
    }

    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// Signs a digest through Turnkey without the blocking bridge. Prefer this
    /// whenever the caller is already async.
    pub async fn sign_hash_async(&self, hash: &[u8; 32]) -> Result<[u8; 64], TurnkeyKeypairError> {
        if derivation::is_derivation_input(hash) {
            return Err(KeypairError::DerivationInput.into());
        }
        self.sign_digest(hash).await
    }

    /// Signs an arbitrary message the way Solana's secp256r1 precompile verifies
    /// it: ECDSA over SHA-256 of the message, low-S. Mirrors
    /// [`zolana_keypair::SigningKey::sign_message`] on this rail.
    ///
    /// The digest is computed here and sent with `HASH_FUNCTION_NO_OP` rather
    /// than handing Turnkey the message with `HASH_FUNCTION_SHA256`, so there is
    /// one signing path and the response is verified against a digest this
    /// process computed.
    pub async fn sign_message_async(
        &self,
        message: &[u8],
    ) -> Result<[u8; 64], TurnkeyKeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput.into());
        }
        self.sign_digest(&hash::sha256(message)).await
    }

    async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], TurnkeyKeypairError> {
        let raw = self
            .activities
            .sign_raw_payload(
                &self.key_ref.organization_id,
                &self.key_ref.private_key_id,
                digest,
                PayloadHashFunction::NoOp,
            )
            .await?;
        let signature = codec::p256_signature(&raw)?;
        if !self.signing_pubkey.verify_hash(digest, &signature) {
            return Err(TurnkeyKeypairError::SignatureKeyMismatch {
                key_id: self.key_ref.private_key_id.clone(),
            });
        }
        Ok(signature)
    }
}

/// Hand-written so the supplied role secrets cannot reach a log. Only the remote
/// reference and public halves are printed.
impl fmt::Debug for TurnkeyP256ShieldedKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnkeyP256ShieldedKeypair")
            .field("key_ref", &self.key_ref)
            .field("p256_pubkey", &hex::encode(self.p256_pubkey.as_bytes()))
            .field(
                "viewing_pubkey",
                &hex::encode(self.viewing_key.pubkey().as_bytes()),
            )
            .field("nullifier_key", &"<redacted>")
            .finish()
    }
}

/// Accepts either SEC1 encoding Turnkey may report and normalizes to compressed,
/// which is what a shielded [`PublicKey`] carries.
fn compressed_pubkey(bytes: &[u8]) -> Result<P256Pubkey, TurnkeyKeypairError> {
    let pubkey = p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| {
        TurnkeyKeypairError::malformed(
            "P-256 public key",
            format!(
                "{} bytes is not a SEC1 point; expected 33 compressed or 65 uncompressed",
                bytes.len()
            ),
        )
    })?;
    Ok(P256Pubkey::from_p256(&pubkey))
}

impl ShieldedKeypairTrait for TurnkeyP256ShieldedKeypair {
    fn signing_pubkey(&self) -> PublicKey {
        self.signing_pubkey
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.viewing_key.pubkey()
    }

    fn curve(&self) -> Curve {
        Curve::P256
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

    /// SHA-256 of the message, then the digest path, matching what Solana's
    /// secp256r1 precompile verifies. Hashing happens here so there is one
    /// remote signing path and one digest to verify the response against.
    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput);
        }
        self.sign_hash(&hash::sha256(message))
    }

    /// `hash` is the `private_tx_hash` the SPP proof commits to, signed as a
    /// prehash and normalized to low-S, so the bytes match what a software key
    /// would return for the same digest.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(hash) {
            return Err(KeypairError::DerivationInput);
        }
        let digest = *hash;
        let activities = Arc::clone(&self.activities);
        let key_ref = self.key_ref.clone();
        let signing_pubkey = self.signing_pubkey;

        self.executor
            .block_on(async move {
                let raw = activities
                    .sign_raw_payload(
                        &key_ref.organization_id,
                        &key_ref.private_key_id,
                        &digest,
                        PayloadHashFunction::NoOp,
                    )
                    .await?;
                let signature = codec::p256_signature(&raw)?;
                if !signing_pubkey.verify_hash(&digest, &signature) {
                    return Err(TurnkeyKeypairError::SignatureKeyMismatch {
                        key_id: key_ref.private_key_id.clone(),
                    });
                }
                Ok(signature)
            })
            .map_err(|_| KeypairError::SigningFailed)
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

// Forwards to the caller-supplied viewing key. Required alongside
// `ShieldedKeypairTrait` for this backend to be a `KeypairWalletAuthority`; on
// this rail the key was supplied rather than derived, but it is held the same.
zolana_keypair::forward_viewing_key_trait!(TurnkeyP256ShieldedKeypair => viewing_key);
