//! Reject duplicate fields before a reference verifier interprets JSON metadata.

use std::fmt;

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;

use super::TeeError;

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                }
                Ok(Unique(Value::Object(values)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element::<Unique>()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(value)))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Unique, E> {
                Ok(Unique(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Unique, E> {
                Ok(Unique(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| Unique(value.into()))
                    .ok_or_else(|| de::Error::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(value.into())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(value)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

pub(super) fn unique_json(bytes: &[u8]) -> Result<Value, TeeError> {
    let Unique(json) =
        serde_json::from_slice::<Unique>(bytes).map_err(|_| TeeError::PolicyRepository)?;
    Ok(json)
}

pub(super) fn metadata(bytes: &[u8], role: &str) -> Result<(), TeeError> {
    let json = unique_json(bytes)?;
    let signed = json
        .get("signed")
        .and_then(Value::as_object)
        .ok_or(TeeError::PolicyRepository)?;
    let version = signed
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(TeeError::PolicyRepository)?;
    if version == 0
        || version > (1 << 53) - 1
        || signed.get("_type").and_then(Value::as_str) != Some(role)
        || signed
            .get("expires")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<jiff::Timestamp>().ok())
            .is_none()
    {
        return Err(TeeError::PolicyRepository);
    }
    if role == "targets"
        && signed
            .get("delegations")
            .is_some_and(|value| !value.is_null())
    {
        return Err(TeeError::PolicyRepository);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_fields_are_rejected_at_every_nesting_level() {
        for bytes in [
            br#"{"version":1,"version":1}"#.as_slice(),
            br#"{"files":{"root.json":"first","root.json":"second"}}"#,
            br#"{"signed":{"roles":[{"threshold":1,"threshold":2}]}}"#,
        ] {
            assert!(unique_json(bytes).is_err());
        }
    }
}
