use std::time::Duration;

use solana_address::Address;
use solana_signature::Signature;
use thiserror::Error;
use zolana_indexer_api::Base64String;
use zolana_ring_client::{
    rpc::{Attestation, AuditorKeyAttestation, AuthorityAuth, ReadAuth},
    ReaderKey,
};

use crate::{origins::Origins, webauthn};

pub const AUTH_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Unauthorized {
    #[error("request timestamp is stale")]
    StaleTimestamp,
    #[error("reader is not a tagged ed25519 or P-256 key")]
    UnknownReaderKey,
    #[error("a P-256 reader signs through WebAuthn")]
    PasskeyNeedsAssertion,
    #[error("an ed25519 reader does not carry a WebAuthn assertion")]
    UnexpectedAssertion,
    #[error("signature does not cover the request")]
    BadSignature,
    #[error("client data is not a WebAuthn assertion")]
    NotAnAssertion,
    #[error("challenge does not cover the request")]
    ChallengeMismatch,
    #[error("origin is not allowed to read through a passkey")]
    OriginNotAllowed,
    #[error("cross origin WebAuthn assertions are not accepted")]
    CrossOriginAssertion,
    #[error("authenticator data names another relying party")]
    RelyingPartyMismatch,
    #[error("passkey read needs user verification")]
    UserVerificationMissing,
    #[error("ring has no config on chain")]
    NoConfig,
    #[error("service auditor key does not match the ring config")]
    AuditorKeyMismatch,
    #[error("reader has no active grant")]
    NotGranted,
    #[error("nonce is invalid")]
    InvalidNonce,
    #[error("nonce was already accepted")]
    Replay,
    #[error("request names another cluster")]
    ClusterMismatch,
    #[error("signer is neither the program upgrade authority nor the config authority")]
    NotRingAuthority,
}

/// The reader whose key signed `attestation`. The reader key tag picks the verifier.
pub fn check_read(
    auth: &ReadAuth,
    attestation: &[u8],
    now: u64,
    origins: &Origins,
) -> Result<ReaderKey, Unauthorized> {
    fresh(now, auth.timestamp)?;
    let reader = <[u8; 34]>::try_from(auth.reader.0.as_slice())
        .ok()
        .and_then(|tagged| ReaderKey::from_bytes(tagged).ok())
        .ok_or(Unauthorized::UnknownReaderKey)?;
    let signature = &auth.signature.0;
    match (reader, &auth.webauthn) {
        (ReaderKey::Ed25519(_), Some(_)) => return Err(Unauthorized::UnexpectedAssertion),
        (ReaderKey::P256(_), None) => return Err(Unauthorized::PasskeyNeedsAssertion),
        (ReaderKey::Ed25519(key), None) => verify_ed25519(key.address(), signature, attestation)?,
        (ReaderKey::P256(key), Some(assertion)) => {
            webauthn::verify(assertion, signature, &key, attestation, origins)?
        }
    }
    Ok(reader)
}

/// The signing authority and nonce. The service signs its own ring and cluster into
/// the attestation, a client names them but never chooses them.
pub(crate) fn check_authority(
    auth: &AuthorityAuth,
    ring: Address,
    genesis_hash: [u8; 32],
    now: u64,
) -> Result<(Address, [u8; 32]), Unauthorized> {
    fresh(now, auth.timestamp)?;
    if auth.genesis_hash.0 != genesis_hash {
        return Err(Unauthorized::ClusterMismatch);
    }
    let nonce = nonce(&auth.nonce)?;
    let attestation = AuditorKeyAttestation { ring, genesis_hash }.message(auth.timestamp, &nonce);
    verify_ed25519(auth.authority.0, &auth.signature.0, &attestation)?;
    Ok((auth.authority.0, nonce))
}

fn verify_ed25519(signer: Address, signature: &[u8], message: &[u8]) -> Result<(), Unauthorized> {
    <[u8; 64]>::try_from(signature)
        .is_ok_and(|signature| Signature::from(signature).verify(signer.as_ref(), message))
        .then_some(())
        .ok_or(Unauthorized::BadSignature)
}

/// One clock reading serves the skew rule and the nonce eviction window.
fn fresh(now: u64, timestamp: u64) -> Result<(), Unauthorized> {
    if now.abs_diff(timestamp) > AUTH_SKEW.as_secs() {
        return Err(Unauthorized::StaleTimestamp);
    }
    Ok(())
}

pub(crate) fn nonce(raw: &Base64String) -> Result<[u8; 32], Unauthorized> {
    raw.0
        .as_slice()
        .try_into()
        .map_err(|_| Unauthorized::InvalidNonce)
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use solana_keypair::Keypair;
    use solana_signer::Signer;

    use zolana_ring_client::rpc::{unix_now, GetDecryptedTransactionsRequest, ReadAttestation};

    use super::*;

    const RING: Address = Address::new_from_array([5; 32]);

    fn wallet() -> Keypair {
        Keypair::new_from_array([42; 32])
    }

    fn signed_auth() -> ReadAuth {
        GetDecryptedTransactionsRequest::read(RING)
            .at(unix_now().expect("clock"))
            .sign(&wallet())
            .expect("signed request")
            .auth
    }

    fn decide(auth: &ReadAuth) -> Result<ReaderKey, Unauthorized> {
        decide_at(auth, unix_now().expect("clock"))
    }

    fn decide_at(auth: &ReadAuth, now: u64) -> Result<ReaderKey, Unauthorized> {
        let nonce: [u8; 32] = auth.nonce.0.as_slice().try_into().unwrap_or([0; 32]);
        let attestation = ReadAttestation {
            ring: RING,
            cursor: None,
            limit: None,
        }
        .message(auth.timestamp, &nonce);
        check_read(auth, &attestation, now, &Origins::default())
    }

    fn assertion() -> zolana_ring_client::rpc::WebAuthnAssertion {
        zolana_ring_client::rpc::WebAuthnAssertion {
            authenticator_data: vec![1; 37].into(),
            client_data_json: b"{}".to_vec().into(),
        }
    }

    #[test]
    fn a_reader_key_the_service_cannot_verify_a_signature_against_is_refused() {
        assert_eq!(
            decide(&signed_auth()).expect("wallet claim"),
            ReaderKey::ed25519(wallet().pubkey()).expect("reader key")
        );

        // A PDA tag, and reader bytes that are not a tagged key at all.
        let mut pda = signed_auth();
        pda.reader.0[0] = 2;
        let mut short = signed_auth();
        short.reader.0.pop();
        for auth in [pda, short] {
            assert_eq!(decide(&auth), Err(Unauthorized::UnknownReaderKey));
        }
    }

    /// An assertion and a raw signature are never interchangeable.
    #[test]
    fn the_signature_scheme_must_match_the_declared_reader_key() {
        let mut passkey_tag = signed_auth();
        passkey_tag.reader = ReaderKey::p256(
            zolana_ring_client::P256ReaderKey::from_bytes(
                hex::decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .expect("passkey reader")
        .to_bytes()
        .to_vec()
        .into();
        assert_eq!(
            decide(&passkey_tag),
            Err(Unauthorized::PasskeyNeedsAssertion)
        );

        let mut wallet_tag = signed_auth();
        wallet_tag.webauthn = Some(assertion());
        assert_eq!(decide(&wallet_tag), Err(Unauthorized::UnexpectedAssertion));
    }

    #[test]
    fn a_timestamp_outside_the_skew_is_refused_in_both_directions() {
        let now = unix_now().expect("clock");
        for timestamp in [now - AUTH_SKEW.as_secs() - 1, now + AUTH_SKEW.as_secs() + 1] {
            let auth = GetDecryptedTransactionsRequest::read(RING)
                .at(timestamp)
                .sign(&wallet())
                .expect("signed request")
                .auth;
            assert_eq!(decide_at(&auth, now), Err(Unauthorized::StaleTimestamp));
        }
    }

    #[test]
    fn a_timestamp_on_the_skew_boundary_is_accepted() {
        let now = unix_now().expect("clock");
        for timestamp in [now - AUTH_SKEW.as_secs(), now + AUTH_SKEW.as_secs()] {
            let auth = GetDecryptedTransactionsRequest::read(RING)
                .at(timestamp)
                .sign(&wallet())
                .expect("signed request")
                .auth;
            assert!(decide_at(&auth, now).is_ok());
        }
    }

    #[test]
    fn a_nonce_that_is_not_thirty_two_bytes_is_refused() {
        let mut auth = signed_auth();
        auth.nonce.0.pop();
        assert_eq!(nonce(&auth.nonce), Err(Unauthorized::InvalidNonce));
    }
}
