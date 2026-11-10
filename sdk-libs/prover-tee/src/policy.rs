use std::{fmt, marker::PhantomData, time::Duration};

use serde::{
    de::{value::MapAccessDeserializer, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

use super::{Platform, PlatformPolicy, TeeError, MAX_INTEGER};

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

    /// Whole seconds, the fraction is dropped. Refuses less than one second
    /// or more than 2^53 - 1, as a TypeScript client does.
    pub fn with_max_age(mut self, max_age: Duration) -> Result<Self, TeeError> {
        self.max_age_secs = max_age.as_secs();
        self.checked().map_err(TeeError::Policy)
    }

    pub fn from_json(json: &str) -> Result<Self, TeeError> {
        serde_json::from_str(json).map_err(|e| TeeError::Policy(e.to_string()))
    }

    /// A [`TeePolicyFile`] pin or a bare policy.
    pub fn from_file_json(json: &str) -> Result<Self, TeeError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| TeeError::Policy(e.to_string()))?;
        if value.get("deployment").is_none() {
            return serde_json::from_value(value).map_err(|e| TeeError::Policy(e.to_string()));
        }
        serde_json::from_value::<TeePolicyFile>(value)
            .map_err(|e| TeeError::Policy(format!("pin file {e}")))?
            .deployment
            .ok_or_else(|| TeeError::Policy("the pin file pins no deployment".to_string()))
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
    /// The rules every policy meets, bare or signed, read or built.
    fn checked(self) -> Result<Self, String> {
        if self.gpu == GpuRequirement::Required && !self.platform().hosts_gpu() {
            return Err(format!(
                "{} attests no GPU, the policy cannot require one",
                self.platform()
            ));
        }
        if !(1..=MAX_INTEGER).contains(&self.max_age_secs) {
            return Err(format!(
                "max_age_secs {} is not between 1 and 2^53 - 1",
                self.max_age_secs
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

/// Whether `value` is hex in the one spelling the TypeScript SDK reads.
pub(super) fn lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A policy's byte pins, in lowercase hex.
pub(super) mod lower_hex {
    use std::fmt::Display;

    use hex::FromHex;
    use serde::{de::Error, Deserialize, Deserializer};

    pub use hex::serde::serialize;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromHex,
        T::Error: Display,
    {
        decode(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }

    pub(super) fn decode<T>(value: &str) -> Result<T, String>
    where
        T: FromHex,
        T::Error: Display,
    {
        if !super::lowercase_hex(value) {
            return Err("a pin is not lowercase hex".into());
        }
        T::from_hex(value).map_err(|e| e.to_string())
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
            .map(|value| super::lower_hex::decode(value).map_err(D::Error::custom))
            .collect()
    }
}

pub(super) mod hex_pin {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => hex::serde::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        super::lower_hex::deserialize(deserializer).map(Some)
    }
}

/// `T` from a JSON object only. A derived `Deserialize` also reads a struct
/// from a positional array, which the TypeScript SDK refuses.
pub(super) struct Object<T>(pub T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for Fields<T> {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map))
            }
        }

        deserializer.deserialize_map(Fields(PhantomData)).map(Self)
    }
}

/// [`Object`] for a field.
pub(super) fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    Object::deserialize(deserializer).map(|Object(value)| value)
}

/// A list of [`Object`]s for a field.
pub(super) fn objects<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    Vec::<Object<T>>::deserialize(deserializer)
        .map(|objects| objects.into_iter().map(|Object(value)| value).collect())
}

#[cfg(test)]
mod tests;
