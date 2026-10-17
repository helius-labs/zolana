use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zolana_ring_client::P256ReaderKey;

use zolana_ring_client::rpc::WebAuthnAssertion;

use crate::{authorize::Unauthorized, origins::Origins};

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const AUTHENTICATOR_DATA_MIN: usize = 37;

/// A passkey signs its authenticator data and the hash of client data whose challenge
/// is the SHA-256 of the attestation.
pub(crate) fn verify(
    assertion: &WebAuthnAssertion,
    signature_der: &[u8],
    pubkey: &P256ReaderKey,
    attestation: &[u8],
    origins: &Origins,
) -> Result<(), Unauthorized> {
    let client: ClientData = serde_json::from_slice(&assertion.client_data_json.0)
        .map_err(|_| Unauthorized::NotAnAssertion)?;
    if client.kind != "webauthn.get" {
        return Err(Unauthorized::NotAnAssertion);
    }
    if client.cross_origin || client.top_origin.is_some() {
        return Err(Unauthorized::CrossOriginAssertion);
    }
    if client.challenge != URL_SAFE_NO_PAD.encode(Sha256::digest(attestation)) {
        return Err(Unauthorized::ChallengeMismatch);
    }
    if !origins.allows(client.origin) {
        return Err(Unauthorized::OriginNotAllowed);
    }
    let relying_party_id = origins
        .relying_party_id()
        .ok_or(Unauthorized::OriginNotAllowed)?;
    let data = &assertion.authenticator_data.0;
    if data.len() < AUTHENTICATOR_DATA_MIN {
        return Err(Unauthorized::NotAnAssertion);
    }
    if data[..32] != Sha256::digest(relying_party_id)[..] {
        return Err(Unauthorized::RelyingPartyMismatch);
    }
    if data[32] & FLAG_USER_PRESENT == 0 || data[32] & FLAG_USER_VERIFIED == 0 {
        return Err(Unauthorized::UserVerificationMissing);
    }
    let signature = Signature::from_der(signature_der).map_err(|_| Unauthorized::BadSignature)?;
    let key = VerifyingKey::from_sec1_bytes(pubkey.as_bytes())
        .map_err(|_| Unauthorized::UnknownReaderKey)?;
    let signed = Sha256::new()
        .chain_update(data)
        .chain_update(Sha256::digest(&assertion.client_data_json.0))
        .finalize();
    key.verify_prehash(&signed, &signature)
        .map_err(|_| Unauthorized::BadSignature)
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
        super::verify(
            &assertion,
            &[0; 8],
            &P256ReaderKey::from_bytes(
                hex::decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            ATTESTATION,
            &origins(),
        )
    }

    /// A registration assertion signs another message, which the reader never made over a read.
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

    /// The length gate keeps the fixed offsets of the relying party hash and flags in bounds.
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
