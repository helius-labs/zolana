//! Explicit fleet pins. Download and signature verification belong to the client.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    verify_with, Anchors, Attestation, AttestedProver, PlatformPolicy, TeeError, TeePolicy,
    NONCE_SIZE,
};

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const MAX_DEPLOYMENTS: usize = 32;

/// One approved generation. Region is metadata, not a claim of attested geography.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TeeDeployment {
    pub id: String,
    pub region: String,
    pub policy: TeePolicy,
}

/// A reviewed, network-specific allowlist of complete deployment policies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TeeFleetPolicy {
    schema_version: u64,
    network: String,
    revision: u64,
    expires_at: u64,
    deployments: Vec<TeeDeployment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetFile {
    schema_version: u64,
    network: String,
    revision: u64,
    expires_at: u64,
    deployments: Vec<DeploymentFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentFile {
    id: String,
    region: String,
    policy: serde_json::Value,
}

impl TeeFleetPolicy {
    /// Parses explicit pins, without downloading or authenticating a publisher.
    pub fn from_json(json: &str, expected_network: &str) -> Result<Self, TeeError> {
        let file: FleetFile = serde_json::from_str(json).map_err(policy_error)?;
        if file.schema_version != 1 {
            return Err(invalid("schema_version"));
        }
        if !identifier(expected_network) || file.network != expected_network {
            return Err(invalid("network"));
        }
        let deployments = file
            .deployments
            .into_iter()
            .map(|entry| {
                // Fleet pins use the same canonical hex and exact fields as TS.
                // The flattened single-policy enum may otherwise ignore fields.
                let policy: TeePolicy =
                    serde_json::from_value(entry.policy.clone()).map_err(policy_error)?;
                let canonical = serde_json::to_value(&policy).map_err(policy_error)?;
                if canonical != entry.policy {
                    return Err(invalid("policy"));
                }
                Ok(TeeDeployment {
                    id: entry.id,
                    region: entry.region,
                    policy,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(file.network, file.revision, file.expires_at, deployments)
    }

    /// Validates all entries together, including unique generation IDs and keys.
    pub fn new(
        network: String,
        revision: u64,
        expires_at: u64,
        deployments: Vec<TeeDeployment>,
    ) -> Result<Self, TeeError> {
        if !identifier(&network) {
            return Err(invalid("network"));
        }
        if revision == 0 || revision > MAX_SAFE_INTEGER {
            return Err(invalid("revision"));
        }
        if expires_at == 0 || expires_at > MAX_SAFE_INTEGER {
            return Err(invalid("expires_at"));
        }
        if deployments.is_empty() || deployments.len() > MAX_DEPLOYMENTS {
            return Err(invalid("deployments"));
        }
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        for entry in &deployments {
            if !identifier(&entry.id) || !identifier(&entry.region) {
                return Err(invalid("deployment identifier"));
            }
            let age = entry.policy.max_age().as_secs();
            if age == 0 || age > MAX_SAFE_INTEGER {
                return Err(invalid("max_age_secs"));
            }
            let key = pinned_key(&entry.policy).ok_or_else(|| invalid("hpke_public_key"))?;
            let has_measurements = match entry.policy.pins() {
                PlatformPolicy::AwsNitro(pins) => !pins.measurements.is_empty(),
                PlatformPolicy::DstackTdx(pins) => !pins.measurements.is_empty(),
            };
            if !has_measurements {
                return Err(invalid("measurements"));
            }
            if !ids.insert(&entry.id) || !keys.insert(key) {
                return Err(invalid("duplicate deployment ID or key"));
            }
        }
        Ok(Self {
            schema_version: 1,
            network,
            revision,
            expires_at,
            deployments,
        })
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn deployments(&self) -> &[TeeDeployment] {
        &self.deployments
    }

    /// A key is a selection hint only; the returned entry does not authenticate it.
    pub fn deployment_for_key(&self, key: &[u8; 32]) -> Option<&TeeDeployment> {
        self.deployments
            .iter()
            .find(|entry| pinned_key(&entry.policy).as_ref() == Some(key))
    }

    pub fn check_time(&self, now_secs: u64) -> Result<(), TeeError> {
        if now_secs > MAX_SAFE_INTEGER || now_secs >= self.expires_at {
            return Err(TeeError::PolicyExpired);
        }
        Ok(())
    }

    /// Verifies fresh evidence against one complete pinned generation.
    pub fn verify(
        &self,
        attestation: Attestation,
        nonce: &[u8; NONCE_SIZE],
        now_secs: u64,
    ) -> Result<AttestedProver, TeeError> {
        self.verify_with(attestation, nonce, now_secs, &Anchors::PRODUCTION)
    }

    /// As [`Self::verify`], with explicit vendor trust anchors for tests.
    pub fn verify_with(
        &self,
        attestation: Attestation,
        nonce: &[u8; NONCE_SIZE],
        now_secs: u64,
        anchors: &Anchors,
    ) -> Result<AttestedProver, TeeError> {
        self.check_time(now_secs)?;
        let deployment = self
            .deployment_for_key(&attestation.hpke_public_key)
            .ok_or(TeeError::HpkeKeyMismatch)?;
        verify_with(attestation, &deployment.policy, nonce, now_secs, anchors)
    }
}

fn pinned_key(policy: &TeePolicy) -> Option<[u8; 32]> {
    match policy.pins() {
        PlatformPolicy::AwsNitro(pins) => pins.hpke_public_key,
        PlatformPolicy::DstackTdx(pins) => Some(pins.hpke_public_key),
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn invalid(field: &str) -> TeeError {
    TeeError::Policy(format!("invalid fleet {field}"))
}

fn policy_error(error: serde_json::Error) -> TeeError {
    TeeError::Policy(error.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn vector() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/tee_fleet_policy.json")).unwrap()
    }

    fn parse(value: &Value) -> Result<TeeFleetPolicy, TeeError> {
        TeeFleetPolicy::from_json(&value.to_string(), "fixture")
    }

    fn fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../prover/tee/testdata")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn nonce(fixture: &Value) -> [u8; NONCE_SIZE] {
        hex::decode(fixture["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn shared_fleet_round_trips_and_authenticates_each_archived_generation() {
        let vector = vector();
        let fleet = parse(&vector["policy"]).unwrap();
        assert_eq!(serde_json::to_value(&fleet).unwrap(), vector["policy"]);
        for case in vector["cases"].as_array().unwrap() {
            let answer = fixture(case["fixture"].as_str().unwrap());
            let prover = fleet
                .verify(
                    serde_json::from_value(answer["attestation"].clone()).unwrap(),
                    &nonce(&answer),
                    answer["captured_at"].as_u64().unwrap(),
                )
                .unwrap();
            assert_eq!(
                fleet
                    .deployment_for_key(&prover.hpke_public_key)
                    .unwrap()
                    .id,
                case["deployment_id"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn rejects_wrong_network_unknown_fields_and_unsupported_or_unbounded_schema() {
        let base = vector()["policy"].clone();
        assert!(TeeFleetPolicy::from_json(&base.to_string(), "mainnet").is_err());
        for (field, value) in [
            ("schema_version", json!(2)),
            ("network", json!("Fixture")),
            ("revision", json!(0)),
            ("revision", json!(MAX_SAFE_INTEGER + 1)),
            ("expires_at", json!(-1)),
            ("expires_at", json!(MAX_SAFE_INTEGER + 1)),
            ("deployments", json!([])),
            (
                "deployments",
                json!(vec![base["deployments"][0].clone(); 33]),
            ),
            ("unexpected", json!(true)),
        ] {
            let mut bad = base.clone();
            bad[field] = value;
            assert!(parse(&bad).is_err(), "accepted {field}");
        }
        for edit in [
            |bad: &mut Value| bad["deployments"][1]["id"] = bad["deployments"][0]["id"].clone(),
            |bad: &mut Value| {
                bad["deployments"][1]["policy"] = bad["deployments"][0]["policy"].clone();
            },
            |bad: &mut Value| {
                bad["deployments"][0]["policy"]
                    .as_object_mut()
                    .unwrap()
                    .remove("hpke_public_key");
            },
            |bad: &mut Value| bad["deployments"][0]["unexpected"] = json!(true),
            |bad: &mut Value| bad["deployments"][0]["policy"]["unexpected"] = json!(true),
            |bad: &mut Value| {
                bad["deployments"][0]["policy"] =
                    json!({"deployment": bad["deployments"][0]["policy"]});
            },
            |bad: &mut Value| bad["deployments"][0]["policy"]["max_age_secs"] = json!(0),
            |bad: &mut Value| {
                bad["deployments"][0]["policy"]["hpke_public_key"] = json!(bad["deployments"][0]
                    ["policy"]["hpke_public_key"]
                    .as_str()
                    .unwrap()
                    .to_uppercase());
            },
            |bad: &mut Value| {
                bad["deployments"][0]["policy"]["measurements"][0]["pcr0"] = json!(bad
                    ["deployments"][0]["policy"]["measurements"][0]["pcr0"]
                    .as_str()
                    .unwrap()
                    .to_uppercase());
            },
        ] {
            let mut bad = base.clone();
            edit(&mut bad);
            assert!(parse(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn never_combines_a_pinned_key_with_another_generations_measurements() {
        let vector = vector();
        let mut file = vector["policy"].clone();
        let first = file["deployments"][0]["policy"]["measurements"].clone();
        file["deployments"][0]["policy"]["measurements"] =
            file["deployments"][1]["policy"]["measurements"].clone();
        file["deployments"][1]["policy"]["measurements"] = first;
        let fleet = parse(&file).unwrap();
        let answer = fixture(vector["cases"][0]["fixture"].as_str().unwrap());
        assert!(matches!(
            fleet.verify(
                serde_json::from_value(answer["attestation"].clone()).unwrap(),
                &nonce(&answer),
                answer["captured_at"].as_u64().unwrap(),
            ),
            Err(TeeError::EnclaveMeasurementNotAllowed)
        ));
    }

    #[test]
    fn rejects_expired_policies_wrong_nonces_and_forged_key_selection_hints() {
        let vector = vector();
        let fleet = parse(&vector["policy"]).unwrap();
        let answer = fixture(vector["cases"][0]["fixture"].as_str().unwrap());
        let now = answer["captured_at"].as_u64().unwrap();
        assert!(fleet
            .verify(
                serde_json::from_value(answer["attestation"].clone()).unwrap(),
                &[0; NONCE_SIZE],
                now,
            )
            .is_err());
        assert!(matches!(
            fleet.verify(
                serde_json::from_value(answer["attestation"].clone()).unwrap(),
                &nonce(&answer),
                fleet.expires_at(),
            ),
            Err(TeeError::PolicyExpired)
        ));
        for key in [
            vector["policy"]["deployments"][1]["policy"]["hpke_public_key"].clone(),
            json!("00".repeat(32)),
        ] {
            let mut forged = answer["attestation"].clone();
            forged["hpke_public_key"] = key;
            assert!(fleet
                .verify(
                    serde_json::from_value(forged).unwrap(),
                    &nonce(&answer),
                    now
                )
                .is_err());
        }
    }
}
