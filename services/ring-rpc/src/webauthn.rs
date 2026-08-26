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

#[cfg(test)]
mod tests {
    use zolana_keypair::ViewingKey;

    use crate::origins::OriginPolicy;

    use super::*;

    const ORIGIN: &str = "http://localhost:3000";
    const RELYING_PARTY: &str = "localhost";
    const ATTESTATION: &[u8] = b"zolana/ring-rpc-read/v1 attestation";

    fn origins() -> Origins {
        OriginPolicy::new(vec![ORIGIN.to_owned()])
            .with_relying_party_id(RELYING_PARTY.to_owned())
            .build()
            .expect("origins")
    }

    fn client_data(kind: &str) -> Vec<u8> {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(ATTESTATION));
        format!(
            r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{ORIGIN}","crossOrigin":false}}"#
        )
        .into_bytes()
    }

    fn authenticator_data(len: usize) -> Vec<u8> {
        let mut data = Sha256::digest(RELYING_PARTY).to_vec();
        data.push(FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
        data.extend_from_slice(&[0, 0, 0, 1]);
        data.truncate(len);
        data
    }

    fn verify(client_data_json: Vec<u8>, authenticator_data: Vec<u8>) -> Result<(), Unauthorized> {
        let assertion = WebAuthnAssertion {
            authenticator_data: authenticator_data.into(),
            client_data_json: client_data_json.into(),
        };
        Verification {
            assertion: &assertion,
            signature_der: &[0; 8],
            pubkey: &ViewingKey::new().pubkey(),
            attestation: ATTESTATION,
            origins: &origins(),
        }
        .verify()
    }

    /// A registration assertion signs a different message, so accepting one
    /// here would verify a signature the reader never made over a read.
    #[test]
    fn client_data_that_is_not_a_get_assertion_is_refused() {
        for json in [
            b"not json at all".to_vec(),
            client_data("webauthn.create"),
            br#"{"challenge":"","origin":""}"#.to_vec(),
        ] {
            assert_eq!(
                verify(json, authenticator_data(AUTHENTICATOR_DATA_MIN)),
                Err(Unauthorized::NotAnAssertion)
            );
        }
    }

    /// The relying party hash and the flag byte are read at fixed offsets, so
    /// the length gate is what keeps a short assertion from being indexed.
    #[test]
    fn authenticator_data_shorter_than_its_fixed_header_is_refused() {
        assert_eq!(
            verify(
                client_data("webauthn.get"),
                authenticator_data(AUTHENTICATOR_DATA_MIN - 1)
            ),
            Err(Unauthorized::NotAnAssertion)
        );
        assert_eq!(
            verify(
                client_data("webauthn.get"),
                authenticator_data(AUTHENTICATOR_DATA_MIN)
            ),
            Err(Unauthorized::BadSignature)
        );
    }
}
