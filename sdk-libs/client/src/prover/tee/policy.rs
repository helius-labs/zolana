use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::TeeError;

/// Pinned per SDK release by `cargo xtask tee-policy`.
const PINNED: &str = include_str!("policy.json");

/// What a prover must prove before it sees a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeePolicy {
    #[serde(with = "hex")]
    pub app_id: [u8; 20],
    #[serde(with = "hex")]
    pub hpke_public_key: [u8; 32],
    /// The `id` the key-provider event names, the KMS root the app keys derive from.
    #[serde(with = "hex")]
    pub key_provider_id: Vec<u8>,
    #[serde(with = "hex_list")]
    pub os_image_hashes: Vec<[u8; 32]>,
    pub measurements: Vec<Measurement>,
    #[serde(with = "hex_list")]
    pub compose_hashes: Vec<[u8; 32]>,
    pub tcb_statuses: Vec<String>,
    pub gpu: GpuRequirement,
    pub max_age_secs: u64,
}

/// The boot measurements of one OS image on one VM shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    #[serde(with = "hex")]
    pub mrtd: [u8; 48],
    #[serde(with = "hex")]
    pub rtmr0: [u8; 48],
    #[serde(with = "hex")]
    pub rtmr1: [u8; 48],
    #[serde(with = "hex")]
    pub rtmr2: [u8; 48],
}

/// Present GPU evidence is always verified, `Required` also refuses its absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuRequirement {
    Optional,
    Required,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedFile {
    deployment: Option<TeePolicy>,
}

impl TeePolicy {
    /// The deployment pinned in the SDK release.
    pub fn pinned() -> Result<Self, TeeError> {
        let file: PinnedFile =
            serde_json::from_str(PINNED).map_err(|e| TeeError::Policy(e.to_string()))?;
        file.deployment.ok_or(TeeError::NoPinnedDeployment)
    }

    pub fn from_json(json: &str) -> Result<Self, TeeError> {
        serde_json::from_str(json).map_err(|e| TeeError::Policy(e.to_string()))
    }

    pub fn max_age(&self) -> Duration {
        Duration::from_secs(self.max_age_secs)
    }
}

mod hex_list {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(values: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(values.iter().map(hex::encode))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<[u8; 32]>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|value| hex::FromHex::from_hex(value).map_err(D::Error::custom))
            .collect()
    }
}
