use serde::{de, Deserialize, Deserializer, Serialize};
use utoipa::{
    openapi::{
        schema::{ObjectBuilder, Schema, Type},
        KnownFormat, RefOr, SchemaFormat,
    },
    PartialSchema, ToSchema,
};

pub const MIN_PAGE_LIMIT: u64 = 1;
pub const PAGE_LIMIT: u64 = 1000;

const LIMIT_EXPECTATION: &str = "a value between 1 and 1000";
const LIMIT_ERROR: &str = "Value must be between 1 and 1000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Limit(pub(crate) u64);

impl Limit {
    pub fn new(value: u64) -> Result<Self, &'static str> {
        if !(MIN_PAGE_LIMIT..=PAGE_LIMIT).contains(&value) {
            Err(LIMIT_ERROR)
        } else {
            Ok(Limit(value))
        }
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl PartialSchema for Limit {
    fn schema() -> RefOr<Schema> {
        let schema = Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::Integer)
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::UInt64)))
                .minimum(Some(MIN_PAGE_LIMIT))
                .maximum(Some(PAGE_LIMIT))
                .build(),
        );
        RefOr::T(schema)
    }
}

impl ToSchema for Limit {}

impl Default for Limit {
    fn default() -> Self {
        Limit(PAGE_LIMIT)
    }
}

impl<'de> Deserialize<'de> for Limit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if !(MIN_PAGE_LIMIT..=PAGE_LIMIT).contains(&value) {
            Err(de::Error::invalid_value(
                de::Unexpected::Unsigned(value),
                &LIMIT_EXPECTATION,
            ))
        } else {
            Ok(Limit(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Limit, PAGE_LIMIT};

    #[test]
    fn constructor_accepts_only_positive_limits_within_page_limit() {
        assert!(Limit::new(0).is_err());
        assert_eq!(Limit::new(1).unwrap().value(), 1);
        assert_eq!(Limit::new(PAGE_LIMIT).unwrap().value(), PAGE_LIMIT);
        assert!(Limit::new(PAGE_LIMIT + 1).is_err());
    }

    #[test]
    fn deserializer_accepts_only_positive_limits_within_page_limit() {
        assert!(serde_json::from_value::<Limit>(serde_json::json!(0)).is_err());
        assert_eq!(
            serde_json::from_value::<Limit>(serde_json::json!(1))
                .unwrap()
                .value(),
            1
        );
        assert_eq!(
            serde_json::from_value::<Limit>(serde_json::json!(PAGE_LIMIT))
                .unwrap()
                .value(),
            PAGE_LIMIT
        );
        assert!(serde_json::from_value::<Limit>(serde_json::json!(PAGE_LIMIT + 1)).is_err());
    }
}
