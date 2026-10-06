use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Platform, PlatformPolicy, TeeError};

/// Pinned per SDK release by `cargo xtask tee-policy`.
const DEFAULT_POLICY: &str = include_str!("policy.json");
const DEFAULT_MAX_AGE_SECS: u64 = 600;

/// What a prover must prove before it sees a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedPolicy")]
pub struct TeePolicy {
    #[serde(flatten)]
    pub(super) pins: PlatformPolicy,
    pub(super) gpu: GpuRequirement,
    pub(super) max_age_secs: u64,
}

#[derive(Deserialize)]
struct UncheckedPolicy {
    #[serde(flatten)]
    pins: PlatformPolicy,
    gpu: GpuRequirement,
    max_age_secs: u64,
}

/// Present GPU evidence is always verified, `Required` also refuses its absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuRequirement {
    Optional,
    Required,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeePolicyFile {
    pub deployment: Option<TeePolicy>,
}

impl TeePolicy {
    #[must_use]
    pub fn new(pins: PlatformPolicy) -> Self {
        Self {
            pins,
            gpu: GpuRequirement::Optional,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
        }
    }

    /// Refuses `Required` on a platform without GPU attestation.
    pub fn with_gpu(mut self, gpu: GpuRequirement) -> Result<Self, TeeError> {
        self.gpu = gpu;
        self.checked().map_err(TeeError::Policy)
    }

    /// Whole seconds, the fraction is dropped.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age_secs = max_age.as_secs();
        self
    }

    /// The deployment pinned in the SDK release.
    pub fn default_deployment() -> Result<Self, TeeError> {
        let file: TeePolicyFile =
            serde_json::from_str(DEFAULT_POLICY).map_err(|e| TeeError::Policy(e.to_string()))?;
        file.deployment.ok_or(TeeError::NoDefaultDeployment)
    }

    pub fn from_json(json: &str) -> Result<Self, TeeError> {
        serde_json::from_str(json).map_err(|e| TeeError::Policy(e.to_string()))
    }

    pub fn platform(&self) -> Platform {
        self.pins.platform()
    }

    pub fn pins(&self) -> &PlatformPolicy {
        &self.pins
    }

    pub fn gpu(&self) -> GpuRequirement {
        self.gpu
    }

    pub fn max_age(&self) -> Duration {
        Duration::from_secs(self.max_age_secs)
    }
}

impl TeePolicy {
    fn checked(self) -> Result<Self, String> {
        if self.gpu == GpuRequirement::Required && !self.platform().hosts_gpu() {
            return Err(format!(
                "{} attests no GPU, the policy cannot require one",
                self.platform()
            ));
        }
        Ok(self)
    }
}

impl TryFrom<UncheckedPolicy> for TeePolicy {
    type Error = String;

    fn try_from(policy: UncheckedPolicy) -> Result<Self, String> {
        Self {
            pins: policy.pins,
            gpu: policy.gpu,
            max_age_secs: policy.max_age_secs,
        }
        .checked()
    }
}

pub(super) mod hex_list {
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
