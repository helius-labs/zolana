//! Encrypts every prover call to the HPKE key verified TEE evidence binds.
//! The wire contract is `spr-prover-tee`; this module adds the session
//! that attests once and reuses the key across a client's calls.

mod session;

use std::collections::BTreeMap;

pub use spr_prover_tee::{
    inspect, verify, verify_with, Anchors, Attestation, AttestedIdentity, AttestedProver,
    DstackIdentity, DstackPolicy, EncryptedRequest, FreshnessPayload, FreshnessSigners,
    GpuRequirement, KeyProvider, NitroIdentity, NitroMeasurement, NitroPolicy, Platform,
    PlatformIdentity, PlatformPolicy, PolicySignature, PolicySigners, ReleasePayload, SignedPart,
    SignedPolicyFile, TdxMeasurement, TeeError, TeePolicy, TeePolicyFile, VerifiedPolicy,
    ATTESTATION_PATH, FRESHNESS_DOMAIN, HEADER_CIPHERTEXT, HEADER_ENC, HEADER_VERSION,
    MAX_ATTESTATION_BYTES, MAX_CLOCK_SKEW_SECS, MAX_SIGNED_POLICY_BYTES, NONCE_SIZE,
    RELEASE_DOMAIN, VERSION,
};

pub(crate) use session::TeeSession;
#[cfg(test)]
pub(crate) use spr_prover_tee::NitroFixture;

use super::endpoint::ProverEndpoint;

/// Each network's policy URL and signers.
const NETWORKS: &str = include_str!("tee/signers.json");

/// A network whose signed policy the SDK pins in `tee/signers.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeeNetwork {
    Mainnet,
    Devnet,
}

impl TeeNetwork {
    pub const ALL: [Self; 2] = [Self::Mainnet, Self::Devnet];

    /// The name `signers.json` and the signed policy use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
        }
    }
}

/// A policy published at `url` as a [`SignedPolicyFile`]: a release that
/// `signers` sign, kept in force by a freshness part that the freshness keys
/// the release names sign. A client downloads it again once it is `max_age_secs`
/// old, when it also attests again, and never uses it past either expiry.
#[derive(Clone, Debug)]
pub struct SignedTeePolicy {
    url: String,
    signers: PolicySigners,
}

impl SignedTeePolicy {
    /// `url` is HTTPS, or HTTP on a loopback host.
    pub fn new(url: impl Into<String>, signers: PolicySigners) -> Result<Self, TeeError> {
        let url = url.into();
        let https = url::Url::parse(&url).is_ok_and(|parsed| match parsed.scheme() {
            "https" => true,
            "http" => ProverEndpoint::parse(&url).is_loopback(),
            _ => false,
        });
        if !https {
            return Err(TeeError::Policy("signed policy URL is not HTTPS".into()));
        }
        Ok(Self { url, signers })
    }

    /// The signed policy the SDK pins for `network`.
    pub fn for_network(network: TeeNetwork) -> Self {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Network {
            url: String,
            public_keys: Vec<String>,
            threshold: usize,
        }
        let network = network.as_str();
        let unknown = format!("signers.json pins no policy for {network}");
        let mut networks: BTreeMap<String, Network> =
            serde_json::from_str(NETWORKS).expect(&unknown);
        let found = networks.remove(network).expect(&unknown);
        let keys = found
            .public_keys
            .iter()
            .map(|key| hex::decode(key).ok()?.try_into().ok())
            .collect::<Option<_>>()
            .expect(&unknown);
        PolicySigners::new(network, keys, found.threshold)
            .and_then(|signers| Self::new(found.url, signers))
            .expect(&unknown)
    }
}

#[cfg(test)]
pub(crate) trait FixtureSession {
    /// A session trusting the fixture root in place of the AWS root.
    fn session(&self) -> TeeSession;
}

#[cfg(test)]
impl FixtureSession for NitroFixture {
    fn session(&self) -> TeeSession {
        TeeSession::new(self.policy().clone()).trusting(self.anchors())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signers_json_pins_exactly_the_tee_networks() {
        for network in TeeNetwork::ALL {
            let policy = SignedTeePolicy::for_network(network);
            assert!(policy
                .url
                .ends_with(&format!("/tee-policy/{}.json", network.as_str())));
        }
        let pinned: BTreeMap<String, serde_json::Value> = serde_json::from_str(NETWORKS).unwrap();
        assert_eq!(pinned.len(), TeeNetwork::ALL.len());
    }
}
