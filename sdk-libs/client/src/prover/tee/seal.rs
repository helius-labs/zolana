use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeS,
    Serializable,
};
use rand_core::{OsRng, UnwrapErr};
use zeroize::Zeroizing;

use super::{TeeError, HPKE_INFO, RESPONSE_EXPORT};

/// One request sealed to the attested key, holding the key its answer opens with.
pub struct SealedRequest {
    pub enc: String,
    pub body: Vec<u8>,
    response_key: Zeroizing<[u8; 32]>,
}

impl SealedRequest {
    /// Binds `method` and the raw `request_uri` as AAD, so the sealed body
    /// opens only on the route and job it was sent to.
    pub fn seal(
        hpke_public_key: &[u8; 32],
        method: &str,
        request_uri: &str,
        plaintext: &[u8],
    ) -> Result<Self, TeeError> {
        let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(hpke_public_key)
            .map_err(|_| TeeError::Sealing("malformed HPKE public key"))?;
        let (encapped, mut context) =
            hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &public_key,
                HPKE_INFO,
                &mut UnwrapErr(OsRng),
            )
            .map_err(|_| TeeError::Sealing("HPKE setup failed"))?;
        let body = context
            .seal(plaintext, request_aad(method, request_uri).as_bytes())
            .map_err(|_| TeeError::Sealing("HPKE seal failed"))?;
        let mut response_key = Zeroizing::new([0u8; 32]);
        context
            .export(RESPONSE_EXPORT, response_key.as_mut())
            .map_err(|_| TeeError::Sealing("HPKE export failed"))?;
        Ok(Self {
            enc: hex::encode(encapped.to_bytes()),
            body,
            response_key,
        })
    }

    /// Returns the status and body the prover sealed inside its answer.
    pub fn open(&self, sealed: &[u8]) -> Result<(u16, Vec<u8>), TeeError> {
        open_response(&self.response_key, sealed)
    }
}

/// The response key is single use, so the zero nonce never repeats under it.
pub fn open_response(key: &[u8; 32], sealed: &[u8]) -> Result<(u16, Vec<u8>), TeeError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| TeeError::Sealing("bad response key"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&[0; 12]), sealed)
        .map_err(|_| TeeError::Sealing("response does not open"))?;
    let (status, body) = plaintext
        .split_first_chunk::<2>()
        .ok_or(TeeError::Sealing("response too short"))?;
    Ok((u16::from_be_bytes(*status), body.to_vec()))
}

fn request_aad(method: &str, request_uri: &str) -> String {
    format!("{method} {request_uri}")
}
