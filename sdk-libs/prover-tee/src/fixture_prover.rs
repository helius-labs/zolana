//! The receiving side of the wire contract, for tests of code that seals a
//! request or reads an answer. The real receiver is the Go prover.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    Serializable,
};
use rand_core::{OsRng, TryRngCore};

use crate::{encryption::request_aad, TeeError, HPKE_INFO, RESPONSE_EXPORT};

/// A prover key derived with RFC 9180 `DeriveKeyPair` from `ikm`.
pub struct FixtureProver {
    private_key: <X25519HkdfSha256 as Kem>::PrivateKey,
    public_key: [u8; 32],
}

/// One opened request and the key its answer is sealed under.
pub struct OpenedRequest {
    pub plaintext: Vec<u8>,
    pub response_key: [u8; 32],
}

impl FixtureProver {
    pub fn from_ikm(ikm: &[u8]) -> Self {
        let (private_key, public_key) = X25519HkdfSha256::derive_keypair(ikm);
        Self {
            private_key,
            public_key: public_key.to_bytes().into(),
        }
    }

    pub fn hpke_public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Opens a request sent as `method request_uri`, with `enc` from
    /// `Zolana-Tee-Enc` and `body` the encrypted bytes.
    pub fn open(
        &self,
        method: &str,
        request_uri: &str,
        enc: &[u8],
        body: &[u8],
    ) -> Result<OpenedRequest, TeeError> {
        let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc)
            .map_err(|_| TeeError::Encryption("malformed encapsulated key"))?;
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &self.private_key,
            &encapped,
            HPKE_INFO,
        )
        .map_err(|_| TeeError::Encryption("HPKE setup failed"))?;
        let plaintext = receiver
            .open(body, request_aad(method, request_uri).as_bytes())
            .map_err(|_| TeeError::Encryption("request does not decrypt"))?;
        let mut response_key = [0u8; 32];
        receiver
            .export(RESPONSE_EXPORT, &mut response_key)
            .map_err(|_| TeeError::Encryption("HPKE export failed"))?;
        Ok(OpenedRequest {
            plaintext,
            response_key,
        })
    }
}

/// An answer's wire bytes: a fresh nonce, then AES-256-GCM over the status as
/// a big-endian `u16` followed by the body.
pub fn seal_response(
    response_key: &[u8; 32],
    status: u16,
    body: &[u8],
) -> Result<Vec<u8>, TeeError> {
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| TeeError::Encryption("no OS randomness for the response nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(response_key)
        .map_err(|_| TeeError::Encryption("bad response key"))?;
    let mut plaintext = status.to_be_bytes().to_vec();
    plaintext.extend_from_slice(body);
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| TeeError::Encryption("response encryption failed"))?;
    Ok([nonce.as_slice(), &sealed].concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::decrypt_response;
    use crate::EncryptedRequest;

    #[test]
    fn a_sealed_request_opens_only_on_its_route_and_its_answer_reads_back() {
        let prover = FixtureProver::from_ikm(&[0x5a; 32]);
        let sent = EncryptedRequest::encrypt(
            &prover.hpke_public_key(),
            "POST",
            "/v1/zolana/prove/transfer_2_2?api-key=k",
            br#"{"inputs":["secret"]}"#,
        )
        .unwrap();
        let enc = hex::decode(&sent.enc).unwrap();

        let opened = prover
            .open("POST", "/v1/zolana/prove/transfer_2_2", &enc, &sent.body)
            .unwrap();
        assert_eq!(opened.plaintext, br#"{"inputs":["secret"]}"#);
        assert_eq!(&opened.response_key, sent.response_key());
        assert!(prover
            .open("POST", "/v1/zolana/prove/merge_8_1", &enc, &sent.body)
            .is_err());

        let answer = seal_response(&opened.response_key, 200, br#"{"proof":"ok"}"#).unwrap();
        assert_eq!(
            decrypt_response(sent.response_key(), &answer).unwrap(),
            (200, br#"{"proof":"ok"}"#.to_vec())
        );
    }
}
