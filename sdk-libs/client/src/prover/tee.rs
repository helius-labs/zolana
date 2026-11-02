//! Encrypts every prover call to the HPKE key verified TEE evidence binds.
//! The wire contract is `spr-prover-tee`; this module adds the session
//! that attests once and reuses the key across a client's calls.

mod session;

use std::{collections::BTreeMap, time::Duration};

pub use spr_prover_tee::{
    inspect, verify, verify_with, Anchors, Attestation, AttestedIdentity, AttestedProver,
    DstackIdentity, DstackPolicy, EncryptedRequest, GpuRequirement, KeyProvider, NitroIdentity,
    NitroMeasurement, NitroPolicy, Platform, PlatformIdentity, PlatformPolicy, PolicyPayload,
    PolicySignature, PolicySigners, SignedPolicyFile, TdxMeasurement, TeeError, TeePolicy,
    TeePolicyFile, ATTESTATION_PATH, HEADER_CIPHERTEXT, HEADER_ENC, HEADER_VERSION,
    MAX_ATTESTATION_BYTES, MAX_SIGNED_POLICY_BYTES, NONCE_SIZE, POLICY_DOMAIN, VERSION,
};

pub(crate) use session::TeeSession;
#[cfg(test)]
pub(crate) use spr_prover_tee::NitroFixture;

use super::endpoint::ProverEndpoint;

/// How long a downloaded policy stands before the next call downloads it again.
const REFRESH: Duration = Duration::from_secs(300);
/// Each network's policy URL and signers.
const NETWORKS: &str = include_str!("tee/signers.json");

/// A policy published at `url` as a [`SignedPolicyFile`] that `signers` sign.
/// A client downloads it again every five minutes and never uses it past its expiry.
#[derive(Clone, Debug)]
pub struct SignedTeePolicy {
    url: String,
    signers: PolicySigners,
    refresh: Duration,
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
        Ok(Self {
            url,
            signers,
            refresh: REFRESH,
        })
    }

    /// The signed policy the SDK pins for `network`, such as `mainnet`.
    pub fn for_network(network: &str) -> Result<Self, TeeError> {
        #[derive(serde::Deserialize)]
        struct Network {
            url: String,
            public_keys: Vec<String>,
            threshold: usize,
        }
        let unknown = || TeeError::Policy(format!("the SDK pins no signed policy for {network}"));
        let mut networks: BTreeMap<String, Network> =
            serde_json::from_str(NETWORKS).map_err(|_| unknown())?;
        let found = networks.remove(network).ok_or_else(unknown)?;
        let keys = found
            .public_keys
            .iter()
            .map(|key| hex::decode(key).ok()?.try_into().ok())
            .collect::<Option<_>>()
            .ok_or_else(unknown)?;
        Self::new(
            found.url,
            PolicySigners::new(network, keys, found.threshold)?,
        )
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
    fn mainnet_is_pinned_and_other_networks_are_not() {
        let mainnet = SignedTeePolicy::for_network("mainnet").unwrap();
        assert!(mainnet.url.ends_with("/tee-policy/mainnet.json"));
        assert!(SignedTeePolicy::for_network("nowhere").is_err());
    }
}
