//! Number-or-decimal-string deserializers for unbounded wire integers.
//!
//! Serialization stays a bare JSON number. The string form is reader
//! tolerance for fields whose domain can exceed `2^53` (see `docs/spec.md`).

use std::fmt;

use serde::de::{self, Deserializer, Visitor};

pub fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct U64Visitor;

    impl<'de> Visitor<'de> for U64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an unsigned integer or string containing an unsigned integer")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u64, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<u64, E>
        where
            E: de::Error,
        {
            value
                .parse::<u64>()
                .map_err(|e| de::Error::custom(format!("Invalid unsigned integer value: {e}")))
        }
    }

    deserializer.deserialize_any(U64Visitor)
}

/// `visit_u64` is required: under `deserialize_any`, `serde_json` sends
/// non-negative numbers there. Light's helper is unsigned-only and has no
/// signed counterpart.
pub fn deserialize_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    struct I64Visitor;

    impl<'de> Visitor<'de> for I64Visitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an integer or string containing an integer")
        }

        fn visit_i64<E>(self, value: i64) -> Result<i64, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_u64<E>(self, value: u64) -> Result<i64, E>
        where
            E: de::Error,
        {
            i64::try_from(value).map_err(|_| {
                de::Error::custom(format!(
                    "Invalid signed integer value: {value} out of range for i64"
                ))
            })
        }

        fn visit_str<E>(self, value: &str) -> Result<i64, E>
        where
            E: de::Error,
        {
            value
                .parse::<i64>()
                .map_err(|e| de::Error::custom(format!("Invalid signed integer value: {e}")))
        }
    }

    deserializer.deserialize_any(I64Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    struct Unsigned {
        #[serde(deserialize_with = "deserialize_u64")]
        value: u64,
    }

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    struct Signed {
        #[serde(deserialize_with = "deserialize_i64")]
        value: i64,
    }

    #[test]
    fn string_and_number_bodies_agree_for_u64() {
        let from_number: Unsigned = serde_json::from_str(r#"{"value":9007199254740993}"#).unwrap();
        let from_string: Unsigned =
            serde_json::from_str(r#"{"value":"9007199254740993"}"#).unwrap();
        assert_eq!(from_number, from_string);
        assert_eq!(from_number.value, 9007199254740993);
    }

    #[test]
    fn string_and_number_bodies_agree_for_i64() {
        let from_number: Signed = serde_json::from_str(r#"{"value":-42}"#).unwrap();
        let from_string: Signed = serde_json::from_str(r#"{"value":"-42"}"#).unwrap();
        assert_eq!(from_number, from_string);
        assert_eq!(from_number.value, -42);
    }

    #[test]
    fn oversized_string_is_refused_for_u64() {
        // One past u64::MAX: parse fails rather than truncating.
        let err = serde_json::from_str::<Unsigned>(r#"{"value":"18446744073709551616"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid unsigned integer value"));
    }

    #[test]
    fn oversized_string_is_refused_for_i64() {
        let err = serde_json::from_str::<Signed>(r#"{"value":"9223372036854775808"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid signed integer value"));
    }

    #[test]
    fn empty_string_is_refused() {
        assert!(serde_json::from_str::<Unsigned>(r#"{"value":""}"#).is_err());
        assert!(serde_json::from_str::<Signed>(r#"{"value":""}"#).is_err());
    }
}
