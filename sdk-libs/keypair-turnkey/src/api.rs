//! [`TurnkeyActivities`] over the real Turnkey API.
//!
//! This is the only module that knows about `turnkey_client`, so the backends
//! stay testable and a caller with its own transport can ignore it.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use turnkey_api_key_stamper::Stamp;
use turnkey_client::{
    generated::{
        immutable::{
            activity::v1::SignRawPayloadIntentV2,
            common::v1::{Curve, HashFunction, PayloadEncoding},
        },
        services::coordinator::public::v1::GetPrivateKeyRequest,
    },
    TurnkeyClient, TurnkeyClientError,
};

use crate::{
    activities::{PayloadHashFunction, RawSignature, RemoteKey, TurnkeyActivities, TurnkeyCurve},
    error::TurnkeyKeypairError,
};

/// Wraps a stamped [`TurnkeyClient`].
///
/// The client's credential must be authorized inside each sub-organization it
/// addresses; activities are stamped in the child's context, not the parent's.
pub struct TurnkeyApiActivities<S: Stamp> {
    client: Arc<TurnkeyClient<S>>,
}

impl<S: Stamp> TurnkeyApiActivities<S> {
    pub fn new(client: Arc<TurnkeyClient<S>>) -> Self {
        Self { client }
    }
}

/// Builds the `SIGN_RAW_PAYLOAD_V2` intent.
///
/// The payload is always sent hex-encoded, because the messages on both rails
/// are raw bytes: the ed25519 derivation envelope and the 32-byte
/// `private_tx_hash` are not valid UTF-8, and a text encoding would either fail
/// or, worse, sign different bytes than intended.
fn sign_raw_payload_intent(
    private_key_id: &str,
    payload: &[u8],
    hash_function: PayloadHashFunction,
) -> SignRawPayloadIntentV2 {
    SignRawPayloadIntentV2 {
        sign_with: private_key_id.to_string(),
        payload: hex::encode(payload),
        encoding: PayloadEncoding::Hexadecimal,
        hash_function: match hash_function {
            // RFC 8032 fixes ed25519's hash; Turnkey rejects anything else here.
            PayloadHashFunction::NotApplicable => HashFunction::NotApplicable,
            // The P-256 rail signs an already-computed digest.
            PayloadHashFunction::NoOp => HashFunction::NoOp,
        },
    }
}

/// Maps a client error to the outcome it actually represents.
///
/// `ActivityRequiresApproval` and `ExceededRetries` are not faults: the first
/// means a policy wants approvers, the second that the activity may still be
/// running. Collapsing either into a generic transport failure would tell a
/// caller to retry when it should wait, or that signing failed when it may not
/// have.
fn classify(error: TurnkeyClientError) -> TurnkeyKeypairError {
    match error {
        TurnkeyClientError::ActivityRequiresApproval(activity) => {
            TurnkeyKeypairError::RequiresApproval(activity)
        }
        TurnkeyClientError::ExceededRetries(attempts) => {
            TurnkeyKeypairError::StillPending(attempts)
        }
        other => TurnkeyKeypairError::Transport(other.to_string()),
    }
}

fn curve_from_api(curve: Curve) -> TurnkeyCurve {
    match curve {
        Curve::Ed25519 => TurnkeyCurve::Ed25519,
        Curve::P256 => TurnkeyCurve::P256,
        _ => TurnkeyCurve::Other,
    }
}

fn decode_hex(field: &'static str, encoded: &str) -> Result<Vec<u8>, TurnkeyKeypairError> {
    hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded))
        .map_err(|error| TurnkeyKeypairError::malformed(field, error.to_string()))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis())
}

#[async_trait]
impl<S: Stamp + Send + Sync> TurnkeyActivities for TurnkeyApiActivities<S> {
    async fn get_private_key(
        &self,
        organization_id: &str,
        private_key_id: &str,
    ) -> Result<RemoteKey, TurnkeyKeypairError> {
        let response = self
            .client
            .get_private_key(GetPrivateKeyRequest {
                organization_id: organization_id.to_string(),
                private_key_id: private_key_id.to_string(),
            })
            .await
            .map_err(classify)?;
        let private_key = response
            .private_key
            .ok_or_else(|| TurnkeyKeypairError::MissingPrivateKey(private_key_id.to_string()))?;
        Ok(RemoteKey {
            curve: curve_from_api(private_key.curve),
            public_key: decode_hex("private key public_key", &private_key.public_key)?,
        })
    }

    async fn sign_raw_payload(
        &self,
        organization_id: &str,
        private_key_id: &str,
        payload: &[u8],
        hash_function: PayloadHashFunction,
    ) -> Result<RawSignature, TurnkeyKeypairError> {
        let activity = self
            .client
            .sign_raw_payload(
                organization_id.to_string(),
                now_ms(),
                sign_raw_payload_intent(private_key_id, payload, hash_function),
            )
            .await
            .map_err(classify)?;
        Ok(RawSignature {
            r: decode_hex("signature r", &activity.result.r)?,
            s: decode_hex("signature s", &activity.result.s)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use zolana_keypair::derivation::ed25519_derivation_message;

    use super::*;

    /// The ed25519 rail must ask for `NOT_APPLICABLE`: Turnkey rejects a
    /// configured hash for EdDSA, and a payload that is not hex-encoded here
    /// would not be the derivation envelope.
    #[test]
    fn ed25519_intent_is_hex_and_not_applicable() {
        let envelope = ed25519_derivation_message(&[3u8; 32]);
        let intent =
            sign_raw_payload_intent("pk-ed25519", &envelope, PayloadHashFunction::NotApplicable);

        assert_eq!(intent.sign_with, "pk-ed25519");
        assert_eq!(intent.payload, hex::encode(&envelope));
        assert_eq!(intent.encoding, PayloadEncoding::Hexadecimal);
        assert_eq!(intent.hash_function, HashFunction::NotApplicable);
    }

    /// The P-256 rail signs a digest, so Turnkey must not hash again.
    #[test]
    fn p256_intent_is_hex_and_no_op() {
        let digest = [5u8; 32];
        let intent = sign_raw_payload_intent("pk-p256", &digest, PayloadHashFunction::NoOp);

        assert_eq!(intent.payload, hex::encode(digest));
        assert_eq!(intent.encoding, PayloadEncoding::Hexadecimal);
        assert_eq!(intent.hash_function, HashFunction::NoOp);
    }

    /// secp256k1 is never a shielded owner, so it maps to a mismatch rather than
    /// to either usable rail.
    #[test]
    fn unsupported_curves_map_to_other() {
        assert_eq!(curve_from_api(Curve::Ed25519), TurnkeyCurve::Ed25519);
        assert_eq!(curve_from_api(Curve::P256), TurnkeyCurve::P256);
        assert_eq!(curve_from_api(Curve::Secp256k1), TurnkeyCurve::Other);
        assert_eq!(curve_from_api(Curve::Unspecified), TurnkeyCurve::Other);
    }

    #[test]
    fn hex_decoding_tolerates_an_0x_prefix() {
        assert_eq!(decode_hex("field", "0xabcd").unwrap(), vec![0xab, 0xcd]);
        assert_eq!(decode_hex("field", "abcd").unwrap(), vec![0xab, 0xcd]);
        assert!(decode_hex("field", "not-hex").is_err());
    }
}
