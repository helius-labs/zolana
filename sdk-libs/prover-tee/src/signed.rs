//! A policy published as one file of two signed parts: a release that enough of
//! the pinned release keys sign, and a short-lived freshness part that the
//! freshness keys the release names sign over that release.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{TeeError, TeePolicy, MAX_INTEGER};

/// Prefixes the release payload bytes a release signer signs.
pub const RELEASE_DOMAIN: &[u8] = b"zolana/prover-tee/v2/release";
/// Prefixes the freshness payload bytes a freshness signer signs.
pub const FRESHNESS_DOMAIN: &[u8] = b"zolana/prover-tee/v2/freshness";
pub const MAX_SIGNED_POLICY_BYTES: usize = 64 << 10;
/// How far past the client's clock a freshness part may be issued, for a
/// device clock that runs behind. A client can therefore hold one part for up
/// to `max_lifetime_secs` plus this, by its own clock.
pub const MAX_CLOCK_SKEW_SECS: u64 = 86_400;

/// A signature and the key it claims.
type KeyedSignature = ([u8; 32], Signature);

/// Keys, `threshold` of which sign each part of their role.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Keys {
    keys: Vec<VerifyingKey>,
    threshold: usize,
}

impl Keys {
    fn new(keys: Vec<[u8; 32]>, threshold: usize) -> Result<Self, &'static str> {
        if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
            return Err("repeat a key");
        }
        if threshold == 0 || threshold > keys.len() {
            return Err("need a threshold between 1 and the number of keys");
        }
        let keys = keys
            .iter()
            .map(VerifyingKey::from_bytes)
            .collect::<Result<_, _>>()
            .map_err(|_| "hold a key that is not an Ed25519 point")?;
        Ok(Self { keys, threshold })
    }

    /// Whether `threshold` distinct keys signed `message`.
    fn signed(&self, message: &[u8], signatures: &[KeyedSignature]) -> bool {
        let mut signed = BTreeSet::new();
        for (key, signature) in signatures {
            if let Some(pinned) = self.keys.iter().find(|pinned| pinned.as_bytes() == key) {
                if pinned.verify_strict(message, signature).is_ok() {
                    signed.insert(*key);
                }
            }
        }
        signed.len() >= self.threshold
    }
}

/// The release keys a client pins for a network, `threshold` of which sign each
/// release. The release names its own freshness keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySigners {
    network: String,
    release: Keys,
}

impl PolicySigners {
    pub fn new(
        network: impl Into<String>,
        keys: Vec<[u8; 32]>,
        threshold: usize,
    ) -> Result<Self, TeeError> {
        let network = network.into();
        let invalid = |reason: &str| TeeError::Policy(format!("policy signers {reason}"));
        if network.is_empty() {
            return Err(invalid("need a network"));
        }
        let release = Keys::new(keys, threshold).map_err(invalid)?;
        Ok(Self { network, release })
    }
}

/// The file a client downloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyFile {
    pub release: SignedPart,
    pub freshness: SignedPart,
}

/// A payload and its signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPart {
    /// Hex of the payload bytes.
    pub payload: String,
    pub signatures: Vec<PolicySignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignature {
    pub public_key: String,
    pub signature: String,
}

/// What the release signers approve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePayload {
    pub network: String,
    pub version: u64,
    /// Unix seconds.
    pub expires_at: u64,
    pub freshness: FreshnessSigners,
    pub policy: TeePolicy,
}

/// Who keeps a release in force, and for how long each freshness part may.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessSigners {
    /// Lowercase hex Ed25519 keys.
    pub public_keys: Vec<String>,
    pub threshold: u64,
    /// The most a freshness part may span, from `issued_at` to `expires_at`.
    /// A client clock behind `issued_at` adds up to [`MAX_CLOCK_SKEW_SECS`].
    pub max_lifetime_secs: u64,
}

/// What a freshness signer vouches for: this release is current until `expires_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessPayload {
    pub network: String,
    pub release_version: u64,
    /// Lowercase hex of the SHA-256 of the release payload bytes.
    pub release_sha256: String,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
}

impl ReleasePayload {
    /// The freshness keys, refusing what a TypeScript client reads differently.
    fn check(&self) -> Result<Keys, TeeError> {
        let max_age = self.policy.max_age().as_secs();
        let FreshnessSigners {
            public_keys,
            threshold,
            max_lifetime_secs,
        } = &self.freshness;
        if self.version == 0
            || self.version > MAX_INTEGER
            || self.expires_at > MAX_INTEGER
            || max_age == 0
            || max_age > MAX_INTEGER
            || *max_lifetime_secs == 0
            || *max_lifetime_secs > MAX_INTEGER
        {
            return Err(refused("malformed"));
        }
        let keys = public_keys
            .iter()
            .map(|key| fixed(key))
            .collect::<Result<_, _>>()?;
        let threshold = usize::try_from(*threshold).map_err(|_| refused("malformed"))?;
        Keys::new(keys, threshold).map_err(|_| refused("malformed"))
    }
}

impl FreshnessPayload {
    /// The freshness of `release`, the release payload bytes, from `issued_at` to `expires_at`.
    pub fn of(
        release: &[u8],
        version: u64,
        network: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            network: network.into(),
            release_version: version,
            release_sha256: hex::encode(Sha256::digest(release)),
            issued_at,
            expires_at,
        }
    }

    /// Refuses what a TypeScript client reads differently.
    fn check(&self) -> Result<(), TeeError> {
        if self.release_version == 0
            || self.release_version > MAX_INTEGER
            || self.expires_at > MAX_INTEGER
            || self.issued_at >= self.expires_at
        {
            return Err(refused("malformed"));
        }
        Ok(())
    }
}

/// A file a client accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPolicy {
    pub release: ReleasePayload,
    /// The release payload bytes, which a later file must repeat under the same version.
    pub release_payload: Vec<u8>,
    pub freshness: FreshnessPayload,
}

impl VerifiedPolicy {
    /// When the policy leaves force: the earlier of the two expiries.
    pub fn expires_at(&self) -> u64 {
        self.release.expires_at.min(self.freshness.expires_at)
    }
}

impl SignedPolicyFile {
    /// Verifies `file` against `signers` at `now`, in Unix seconds.
    pub fn verify(
        file: &[u8],
        signers: &PolicySigners,
        now: u64,
    ) -> Result<VerifiedPolicy, TeeError> {
        let file: Self = serde_json::from_slice(file).map_err(|_| refused("malformed"))?;
        let (release_payload, release_signatures) = file.release.decode()?;
        let (freshness_payload, freshness_signatures) = file.freshness.decode()?;

        let message = [RELEASE_DOMAIN, &release_payload].concat();
        if !signers.release.signed(&message, &release_signatures) {
            return Err(refused("signature"));
        }
        let release: ReleasePayload =
            serde_json::from_slice(&release_payload).map_err(|_| refused("malformed"))?;
        let freshness_keys = release.check()?;
        if release.network != signers.network {
            return Err(refused("network"));
        }
        if now >= release.expires_at {
            return Err(refused("expired"));
        }

        let message = [FRESHNESS_DOMAIN, &freshness_payload].concat();
        if !freshness_keys.signed(&message, &freshness_signatures) {
            return Err(refused("freshness"));
        }
        let freshness: FreshnessPayload =
            serde_json::from_slice(&freshness_payload).map_err(|_| refused("malformed"))?;
        freshness.check()?;
        let binds = FreshnessPayload::of(
            &release_payload,
            release.version,
            &signers.network,
            freshness.issued_at,
            freshness.expires_at,
        );
        if freshness != binds {
            return Err(refused("freshness"));
        }
        if freshness.expires_at - freshness.issued_at > release.freshness.max_lifetime_secs {
            return Err(refused("lifetime"));
        }
        if freshness.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(refused("future"));
        }
        if now >= freshness.expires_at {
            return Err(refused("stale"));
        }
        Ok(VerifiedPolicy {
            release,
            release_payload,
            freshness,
        })
    }
}

impl SignedPart {
    /// The payload bytes and signatures, with no check of the signatures.
    fn decode(&self) -> Result<(Vec<u8>, Vec<KeyedSignature>), TeeError> {
        let signatures = self
            .signatures
            .iter()
            .map(|entry| {
                Ok((
                    fixed(&entry.public_key)?,
                    Signature::from_bytes(&fixed(&entry.signature)?),
                ))
            })
            .collect::<Result<_, TeeError>>()?;
        Ok((lower_hex(&self.payload)?, signatures))
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl SignedPart {
    /// `payload` signed under `domain` by each of `keys`.
    pub fn sign(domain: &[u8], payload: &[u8], keys: &[ed25519_dalek::SigningKey]) -> Self {
        use ed25519_dalek::Signer;

        let message = [domain, payload].concat();
        Self {
            payload: hex::encode(payload),
            signatures: keys
                .iter()
                .map(|key| PolicySignature {
                    public_key: hex::encode(key.verifying_key().as_bytes()),
                    signature: hex::encode(key.sign(&message).to_bytes()),
                })
                .collect(),
        }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl FreshnessSigners {
    /// Any one of `keys`, for parts of at most `max_lifetime_secs`.
    pub fn of(keys: &[ed25519_dalek::SigningKey], max_lifetime_secs: u64) -> Self {
        Self {
            public_keys: keys
                .iter()
                .map(|key| hex::encode(key.verifying_key().as_bytes()))
                .collect(),
            threshold: 1,
            max_lifetime_secs,
        }
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl SignedPolicyFile {
    /// `release` signed by `release_keys`, kept fresh from `issued_at` to
    /// `fresh_until` by `freshness_keys`.
    pub fn sign(
        release: &ReleasePayload,
        release_keys: &[ed25519_dalek::SigningKey],
        (issued_at, fresh_until): (u64, u64),
        freshness_keys: &[ed25519_dalek::SigningKey],
    ) -> Result<Self, serde_json::Error> {
        let payload = serde_json::to_vec(release)?;
        let freshness = FreshnessPayload::of(
            &payload,
            release.version,
            &release.network,
            issued_at,
            fresh_until,
        );
        let freshness = serde_json::to_vec(&freshness)?;
        Ok(Self {
            release: SignedPart::sign(RELEASE_DOMAIN, &payload, release_keys),
            freshness: SignedPart::sign(FRESHNESS_DOMAIN, &freshness, freshness_keys),
        })
    }
}

fn refused(check: &'static str) -> TeeError {
    TeeError::SignedPolicy(check)
}

fn fixed<const N: usize>(hex: &str) -> Result<[u8; N], TeeError> {
    lower_hex(hex)?.try_into().map_err(|_| refused("malformed"))
}

fn lower_hex(hex: &str) -> Result<Vec<u8>, TeeError> {
    if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(refused("malformed"));
    }
    hex::decode(hex).map_err(|_| refused("malformed"))
}

#[cfg(test)]
mod tests;
