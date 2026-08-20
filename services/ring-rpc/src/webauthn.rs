//! Verification of a read attestation signed through WebAuthn, the path a
//! passkey (Touch ID, YubiKey) takes. The authenticator signs
//! `authenticator_data || SHA-256(client_data_json)` and carries the challenge
//! inside `client_data_json`, so the attestation itself is bound through the
//! challenge, `SHA-256(attestation)`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zolana_keypair::P256Pubkey;

use crate::api::WebAuthnAssertion;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
/// rpIdHash(32) || flags(1) || signCount(4).
const AUTHENTICATOR_DATA_MIN: usize = 37;

#[derive(Deserialize)]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: &'a str,
    origin: &'a str,
}

/// `origins` is the exact-match allowlist; the relying party id is the host of
/// the matched origin. An empty allowlist refuses every assertion, so a
/// deployment opts into passkeys by naming the pages that may use them.
pub fn verify(
    assertion: &WebAuthnAssertion,
    signature: &[u8],
    pubkey: &P256Pubkey,
    attestation: &[u8],
    origins: &[String],
) -> Result<(), &'static str> {
    let client: ClientData = serde_json::from_slice(&assertion.client_data_json.0)
        .map_err(|_| "client data is not a WebAuthn assertion")?;
    // A registration response must not stand in for an assertion.
    if client.kind != "webauthn.get" {
        return Err("client data is not a WebAuthn assertion");
    }
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(attestation));
    if client.challenge.trim_end_matches('=') != expected {
        return Err("challenge does not cover this request");
    }
    if !origins.iter().any(|origin| origin == client.origin) {
        return Err("origin is not allowed to read through a passkey");
    }

    let data = &assertion.authenticator_data.0;
    if data.len() < AUTHENTICATOR_DATA_MIN {
        return Err("authenticator data is truncated");
    }
    if data[..32] != Sha256::digest(host(client.origin))[..] {
        return Err("authenticator data names another relying party");
    }
    let flags = data[32];
    if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
        return Err("passkey read needs user verification");
    }

    let signature = Signature::from_der(signature).map_err(|_| "signature is not DER ECDSA")?;
    let key = VerifyingKey::from_sec1_bytes(pubkey.as_bytes())
        .map_err(|_| "reader is not a P-256 key")?;
    let mut signed = Sha256::new();
    signed.update(data);
    signed.update(Sha256::digest(&assertion.client_data_json.0));
    key.verify_prehash(&signed.finalize(), &signature)
        .map_err(|_| "signature does not cover this request")
}

/// `scheme://host[:port][/path]` to `host`, the WebAuthn relying party id of a
/// page served from that origin.
fn host(origin: &str) -> &str {
    let rest = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let rest = rest.split('/').next().unwrap_or(rest);
    rest.rsplit_once(':').map_or(rest, |(host, _)| host)
}
