//! A policy published as one file that enough of the pinned Ed25519 keys sign.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{TeeError, TeePolicy, MAX_INTEGER};

/// Prefixes the payload bytes a signer signs.
pub const POLICY_DOMAIN: &[u8] = b"zolana/prover-tee/v1/policy";
pub const MAX_SIGNED_POLICY_BYTES: usize = 64 << 10;

/// The keys that sign a network's policy, `threshold` of them for each file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySigners {
    network: String,
    keys: Vec<VerifyingKey>,
    threshold: usize,
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
        if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
            return Err(invalid("repeat a key"));
        }
        if threshold == 0 || threshold > keys.len() {
            return Err(invalid("need a threshold between 1 and the number of keys"));
        }
        let keys = keys
            .iter()
            .map(VerifyingKey::from_bytes)
            .collect::<Result<_, _>>()
            .map_err(|_| invalid("hold a key that is not an Ed25519 point"))?;
        Ok(Self {
            network,
            keys,
            threshold,
        })
    }
}

/// The file a client downloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyFile {
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

/// What the signers approve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPayload {
    pub network: String,
    pub version: u64,
    /// Unix seconds.
    pub expires_at: u64,
    pub policy: TeePolicy,
}

impl PolicyPayload {
    /// Refuses what a TypeScript client reads differently.
    pub fn check(&self) -> Result<(), TeeError> {
        let max_age = self.policy.max_age().as_secs();
        if self.version == 0
            || self.version > MAX_INTEGER
            || self.expires_at > MAX_INTEGER
            || max_age == 0
            || max_age > MAX_INTEGER
        {
            return Err(refused("malformed"));
        }
        Ok(())
    }
}

impl SignedPolicyFile {
    /// The payload bytes, with no check of their signatures.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, TeeError> {
        lower_hex(&self.payload)
    }

    /// Verifies `file` against `signers` at `now`, in Unix seconds.
    pub fn verify(
        file: &[u8],
        signers: &PolicySigners,
        now: u64,
    ) -> Result<(PolicyPayload, Vec<u8>), TeeError> {
        let file: Self = serde_json::from_slice(file).map_err(|_| refused("malformed"))?;
        let payload = file.payload_bytes()?;
        let message = [POLICY_DOMAIN, &payload].concat();
        let mut signed = BTreeSet::new();
        for entry in &file.signatures {
            let key: [u8; 32] = fixed(&entry.public_key)?;
            let signature = Signature::from_bytes(&fixed(&entry.signature)?);
            if let Some(pinned) = signers.keys.iter().find(|pinned| *pinned.as_bytes() == key) {
                if pinned.verify_strict(&message, &signature).is_ok() {
                    signed.insert(key);
                }
            }
        }
        if signed.len() < signers.threshold {
            return Err(refused("signature"));
        }
        let approved: PolicyPayload =
            serde_json::from_slice(&payload).map_err(|_| refused("malformed"))?;
        approved.check()?;
        if approved.network != signers.network {
            return Err(refused("network"));
        }
        if now >= approved.expires_at {
            return Err(refused("expired"));
        }
        Ok((approved, payload))
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
mod tests {
    use serde_json::Value;

    use super::*;

    const VECTORS: &str = include_str!("../../../prover/tee/testdata/signed_policy.json");

    #[test]
    fn signed_policy_vectors() {
        let vectors: Value = serde_json::from_str(VECTORS).unwrap();
        let keys = vectors["public_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| fixed(key.as_str().unwrap()).unwrap())
            .collect();
        let signers = PolicySigners::new(
            vectors["network"].as_str().unwrap(),
            keys,
            vectors["threshold"].as_u64().unwrap() as usize,
        )
        .unwrap();
        let now = vectors["now"].as_u64().unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let file = serde_json::to_vec(&case["file"]).unwrap();
            match SignedPolicyFile::verify(&file, &signers, now) {
                Ok((payload, _)) => assert_eq!(
                    Some(payload.version),
                    case["version"].as_u64(),
                    "{name} verified"
                ),
                Err(TeeError::SignedPolicy(check)) => {
                    assert_eq!(Some(check), case["error"].as_str(), "{name}")
                }
                Err(error) => panic!("{name}: {error}"),
            }
        }
    }

    #[test]
    fn signers_refuse_a_threshold_they_cannot_meet_or_a_repeated_key() {
        let key = VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&[1; 32])).to_bytes();
        assert!(PolicySigners::new("n", vec![key], 2).is_err());
        assert!(PolicySigners::new("n", vec![key], 0).is_err());
        assert!(PolicySigners::new("n", vec![key, key], 1).is_err());
        assert!(PolicySigners::new("", vec![key], 1).is_err());
        assert!(PolicySigners::new("n", vec![key], 1).is_ok());
    }
}
