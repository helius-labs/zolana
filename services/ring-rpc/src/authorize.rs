use std::time::Duration;

use solana_address::Address;
use solana_signature::Signature;
use thiserror::Error;
use zolana_ring_client::ReaderKey;

use crate::{
    api::{AuditorKeyAttestation, AuthorityAuth, ReadAttestation, ReadAuth, WebAuthnAssertion},
    origins::Origins,
    webauthn,
};

pub const READ_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Claim {
    reader: ReaderKey,
    nonce: [u8; 32],
}

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
    #[error("read nonce is invalid")]
    InvalidNonce,
    #[error("read nonce was already accepted")]
    Replay,
    #[error("request names another cluster")]
    ClusterMismatch,
    #[error("signer is neither the program upgrade authority nor the config authority")]
    NotRingAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct AuthorityClaim {
    authority: Address,
    nonce: [u8; 32],
}

#[must_use]
pub struct AuthorityCheck<'a> {
    auth: &'a AuthorityAuth,
    attestation: &'a AuditorKeyAttestation<'a>,
}

#[must_use]
pub struct TimedAuthorityCheck<'a> {
    auth: &'a AuthorityAuth,
    now: u64,
    attestation: &'a AuditorKeyAttestation<'a>,
}

impl AuthorityClaim {
    pub fn authority(self) -> Address {
        self.authority
    }

    pub fn nonce(self) -> [u8; 32] {
        self.nonce
    }
}

impl<'a> AuthorityCheck<'a> {
    pub fn new(auth: &'a AuthorityAuth, attestation: &'a AuditorKeyAttestation<'a>) -> Self {
        Self { auth, attestation }
    }

    pub fn at(self, now: u64) -> TimedAuthorityCheck<'a> {
        TimedAuthorityCheck {
            auth: self.auth,
            now,
            attestation: self.attestation,
        }
    }
}

impl TimedAuthorityCheck<'_> {
    /// The attestation carries the service genesis hash, the explicit compare only names the error.
    pub fn decide(self) -> Result<AuthorityClaim, Unauthorized> {
        if self.now.abs_diff(self.auth.timestamp) > READ_SKEW.as_secs() {
            return Err(Unauthorized::StaleTimestamp);
        }
        if self.auth.genesis_hash.0 != *self.attestation.genesis_hash {
            return Err(Unauthorized::ClusterMismatch);
        }
        let nonce: [u8; 32] = self
            .auth
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Unauthorized::InvalidNonce)?;
        let signature: [u8; 64] = self
            .auth
            .signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Unauthorized::BadSignature)?;
        let authority = self.auth.authority.0;
        Signature::from(signature)
            .verify(authority.as_ref(), &self.attestation.bytes())
            .then_some(AuthorityClaim { authority, nonce })
            .ok_or(Unauthorized::BadSignature)
    }
}

#[must_use]
pub struct ReadCheck<'a> {
    auth: &'a ReadAuth,
    attestation: &'a ReadAttestation<'a>,
}

#[must_use]
pub struct TimedReadCheck<'a> {
    auth: &'a ReadAuth,
    now: u64,
    attestation: &'a ReadAttestation<'a>,
}

#[must_use]
pub struct ReadyReadCheck<'a, 'o> {
    auth: &'a ReadAuth,
    now: u64,
    attestation: &'a ReadAttestation<'a>,
    origins: &'o Origins,
}

impl Claim {
    pub fn reader_key(self) -> ReaderKey {
        self.reader
    }

    pub fn nonce(self) -> [u8; 32] {
        self.nonce
    }
}

impl<'a> ReadCheck<'a> {
    pub fn new(auth: &'a ReadAuth, attestation: &'a ReadAttestation<'a>) -> Self {
        Self { auth, attestation }
    }

    pub fn at(self, now: u64) -> TimedReadCheck<'a> {
        TimedReadCheck {
            auth: self.auth,
            now,
            attestation: self.attestation,
        }
    }
}

impl<'a> TimedReadCheck<'a> {
    pub fn against<'o>(self, origins: &'o Origins) -> ReadyReadCheck<'a, 'o> {
        ReadyReadCheck {
            auth: self.auth,
            now: self.now,
            attestation: self.attestation,
            origins,
        }
    }
}

impl ReadyReadCheck<'_, '_> {
    pub fn decide(self) -> Result<Claim, Unauthorized> {
        if self.now.abs_diff(self.auth.timestamp) > READ_SKEW.as_secs() {
            return Err(Unauthorized::StaleTimestamp);
        }
        let nonce = self
            .auth
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Unauthorized::InvalidNonce)?;
        let reader = Proof::decode(self.auth)?.verify(&self.attestation.bytes(), self.origins)?;
        Ok(Claim { reader, nonce })
    }
}

enum Proof<'a> {
    Ed25519 {
        reader: ReaderKey,
        signature: [u8; 64],
    },
    Passkey {
        reader: ReaderKey,
        assertion: &'a WebAuthnAssertion,
        signature_der: &'a [u8],
    },
}

impl<'a> Proof<'a> {
    fn decode(auth: &'a ReadAuth) -> Result<Self, Unauthorized> {
        let tagged: [u8; 34] = auth
            .reader
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Unauthorized::UnknownReaderKey)?;
        let reader = ReaderKey::from_bytes(tagged).map_err(|_| Unauthorized::UnknownReaderKey)?;
        match reader {
            ReaderKey::Ed25519(_) => {
                if auth.webauthn.is_some() {
                    return Err(Unauthorized::UnexpectedAssertion);
                }
                let signature = auth
                    .signature
                    .0
                    .as_slice()
                    .try_into()
                    .map_err(|_| Unauthorized::BadSignature)?;
                Ok(Self::Ed25519 { reader, signature })
            }
            ReaderKey::P256(_) => {
                let assertion = auth
                    .webauthn
                    .as_ref()
                    .ok_or(Unauthorized::PasskeyNeedsAssertion)?;
                Ok(Self::Passkey {
                    reader,
                    assertion,
                    signature_der: &auth.signature.0,
                })
            }
        }
    }

    fn verify(self, attestation: &[u8], origins: &Origins) -> Result<ReaderKey, Unauthorized> {
        match self {
            Self::Ed25519 { reader, signature } => {
                let ReaderKey::Ed25519(key) = reader else {
                    return Err(Unauthorized::UnknownReaderKey);
                };
                Signature::from(signature)
                    .verify(key.address().as_ref(), attestation)
                    .then_some(reader)
                    .ok_or(Unauthorized::BadSignature)
            }
            Self::Passkey {
                reader,
                assertion,
                signature_der,
            } => {
                let ReaderKey::P256(key) = reader else {
                    return Err(Unauthorized::UnknownReaderKey);
                };
                webauthn::Verification {
                    assertion,
                    signature_der,
                    pubkey: &key.pubkey(),
                    attestation,
                    origins,
                }
                .verify()?;
                Ok(reader)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use zolana_keypair::ViewingKey;

    use crate::api::{unix_now, GetDecryptedTransactionsRequest};

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

    fn decide(auth: &ReadAuth) -> Result<Claim, Unauthorized> {
        let nonce: [u8; 32] = auth.nonce.0.as_slice().try_into().unwrap_or([0; 32]);
        ReadCheck::new(
            auth,
            &ReadAttestation {
                ring: RING,
                timestamp: auth.timestamp,
                nonce: &nonce,
                cursor: None,
                limit: None,
            },
        )
        .at(unix_now().expect("clock"))
        .against(&Origins::default())
        .decide()
    }

    fn assertion() -> WebAuthnAssertion {
        WebAuthnAssertion {
            authenticator_data: vec![1; 37].into(),
            client_data_json: b"{}".to_vec().into(),
        }
    }

    #[test]
    fn a_reader_key_the_service_cannot_verify_a_signature_against_is_refused() {
        assert_eq!(
            decide(&signed_auth()).expect("wallet claim").reader_key(),
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

    /// The reader key tag picks the verifier, so an assertion and a raw
    /// signature are never interchangeable.
    #[test]
    fn the_signature_scheme_must_match_the_declared_reader_key() {
        let mut passkey_tag = signed_auth();
        passkey_tag.reader = ReaderKey::p256(ViewingKey::new().pubkey())
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
        for timestamp in [now - READ_SKEW.as_secs() - 1, now + READ_SKEW.as_secs() + 1] {
            let auth = GetDecryptedTransactionsRequest::read(RING)
                .at(timestamp)
                .sign(&wallet())
                .expect("signed request")
                .auth;
            assert_eq!(decide(&auth), Err(Unauthorized::StaleTimestamp));
        }
    }

    #[test]
    fn a_nonce_that_is_not_thirty_two_bytes_is_refused() {
        let mut auth = signed_auth();
        auth.nonce.0.pop();
        assert_eq!(decide(&auth), Err(Unauthorized::InvalidNonce));
    }
}
