use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeS,
    Serializable,
};
use rand_core::{OsRng, UnwrapErr};
use zeroize::Zeroizing;

use super::{TeeError, API_KEY_PARAM, HPKE_INFO, RESPONSE_EXPORT};

/// The path the Helius gateway serves the prover under. The prover answers
/// every route under it with the same handler as the bare route.
const GATEWAY_PREFIX: &str = "/v1/zolana";

/// One request encrypted to the attested key, holding the key that decrypts its answer.
pub struct EncryptedRequest {
    pub enc: String,
    pub body: Vec<u8>,
    response_key: Zeroizing<[u8; 32]>,
}

impl EncryptedRequest {
    /// Binds `method` and `request_uri` without its `api-key` pairs as AAD, so
    /// the encrypted body decrypts only on the route it was sent to.
    /// `request_uri` is the path below the prover URL and its query.
    pub fn encrypt(
        hpke_public_key: &[u8; 32],
        method: &str,
        request_uri: &str,
        plaintext: &[u8],
    ) -> Result<Self, TeeError> {
        let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(hpke_public_key)
            .map_err(|_| TeeError::Encryption("malformed HPKE public key"))?;
        let (encapped, mut context) =
            hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &public_key,
                HPKE_INFO,
                &mut UnwrapErr(OsRng),
            )
            .map_err(|_| TeeError::Encryption("HPKE setup failed"))?;
        let body = context
            .seal(plaintext, request_aad(method, request_uri).as_bytes())
            .map_err(|_| TeeError::Encryption("HPKE encryption failed"))?;
        let mut response_key = Zeroizing::new([0u8; 32]);
        context
            .export(RESPONSE_EXPORT, response_key.as_mut())
            .map_err(|_| TeeError::Encryption("HPKE export failed"))?;
        Ok(Self {
            enc: hex::encode(encapped.to_bytes()),
            body,
            response_key,
        })
    }

    /// Returns the status and body the prover encrypted inside its answer.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<(u16, Vec<u8>), TeeError> {
        decrypt_response(&self.response_key, encrypted)
    }

    /// The key that decrypts the answer, for a holder other than the sender.
    /// An HPKE export, it opens no request.
    pub fn response_key(&self) -> &[u8; 32] {
        &self.response_key
    }
}

pub fn decrypt_response(key: &[u8; 32], encrypted: &[u8]) -> Result<(u16, Vec<u8>), TeeError> {
    let (nonce, ciphertext) = encrypted
        .split_first_chunk::<12>()
        .ok_or(TeeError::Encryption("response too short"))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| TeeError::Encryption("bad response key"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| TeeError::Encryption("response does not decrypt"))?;
    let (status, body) = plaintext
        .split_first_chunk::<2>()
        .ok_or(TeeError::Encryption("response too short"))?;
    Ok((u16::from_be_bytes(*status), body.to_vec()))
}

/// The method, route and query minus every `api-key` parameter, so a proxy can
/// move the credential while the route and job stay bound. The route is the
/// path without trailing slashes or [`GATEWAY_PREFIX`], as the Go prover receives it; a client
/// passes the path below its prover URL, so a proxy can serve the prover under
/// any path.
pub(crate) fn request_aad(method: &str, request_uri: &str) -> String {
    let (path, query) = request_uri.split_once('?').unwrap_or((request_uri, ""));
    let path = path
        .strip_prefix(GATEWAY_PREFIX)
        .filter(|route| route.starts_with('/'))
        .unwrap_or(path);
    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            !pair.is_empty()
                && form_urlencoded::parse(pair.as_bytes())
                    .next()
                    .is_none_or(|(key, _)| key != API_KEY_PARAM)
        })
        .collect();
    if kept.is_empty() {
        format!("{method} {path}")
    } else {
        format!("{method} {path}?{}", kept.join("&"))
    }
}
