use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zolana_keypair::P256Pubkey;

use crate::{api::WebAuthnAssertion, authorize::Unauthorized, origins::Origins};

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const AUTHENTICATOR_DATA_MIN: usize = 37;

#[must_use]
pub struct Verification<'a> {
    pub assertion: &'a WebAuthnAssertion,
    pub signature_der: &'a [u8],
    pub pubkey: &'a P256Pubkey,
    pub attestation: &'a [u8],
    pub origins: &'a Origins,
}

impl Verification<'_> {
    pub fn verify(self) -> Result<(), Unauthorized> {
        let client: ClientData = serde_json::from_slice(&self.assertion.client_data_json.0)
            .map_err(|_| Unauthorized::NotAnAssertion)?;
        if client.kind != "webauthn.get" {
            return Err(Unauthorized::NotAnAssertion);
        }
        if client.cross_origin || client.top_origin.is_some() {
            return Err(Unauthorized::CrossOriginAssertion);
        }
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(self.attestation));
        if client.challenge != expected {
            return Err(Unauthorized::ChallengeMismatch);
        }
        if !self.origins.allows(client.origin) {
            return Err(Unauthorized::OriginNotAllowed);
        }
        let relying_party_id = self
            .origins
            .relying_party_id()
            .ok_or(Unauthorized::OriginNotAllowed)?;

        let data = &self.assertion.authenticator_data.0;
        if data.len() < AUTHENTICATOR_DATA_MIN {
            return Err(Unauthorized::NotAnAssertion);
        }
        if data[..32] != Sha256::digest(relying_party_id)[..] {
            return Err(Unauthorized::RelyingPartyMismatch);
        }
        let flags = data[32];
        if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
            return Err(Unauthorized::UserVerificationMissing);
        }

        let signature =
            Signature::from_der(self.signature_der).map_err(|_| Unauthorized::BadSignature)?;
        let key = VerifyingKey::from_sec1_bytes(self.pubkey.as_bytes())
            .map_err(|_| Unauthorized::UnknownReaderKey)?;
        let mut signed = Sha256::new();
        signed.update(data);
        signed.update(Sha256::digest(&self.assertion.client_data_json.0));
        key.verify_prehash(&signed.finalize(), &signature)
            .map_err(|_| Unauthorized::BadSignature)
    }
}

#[derive(Deserialize)]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: &'a str,
    origin: &'a str,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
    #[serde(default, rename = "topOrigin")]
    top_origin: Option<&'a str>,
}
