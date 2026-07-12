use base64::{engine::general_purpose::STANDARD, Engine as _};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};
use utoipa::{
    openapi::{
        schema::{ObjectBuilder, Schema, Type},
        RefOr,
    },
    PartialSchema, ToSchema,
};

use serde::Serializer;

#[derive(Default, Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Base64String(pub Vec<u8>);

impl Serialize for Base64String {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64_encoded = STANDARD.encode(&self.0);
        serializer.serialize_str(&base64_encoded)
    }
}

struct Base64Visitor;

impl<'de> Visitor<'de> for Base64Visitor {
    type Value = Base64String;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a base64 encoded string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        STANDARD
            .decode(value)
            .map(Base64String)
            .map_err(|e| E::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for Base64String {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Base64Visitor)
    }
}

impl PartialSchema for Base64String {
    fn schema() -> RefOr<Schema> {
        let example = serde_json::Value::String("SGVsbG8sIFdvcmxkIQ==".to_string());
        let schema = Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .description(Some("A base 64 encoded string."))
                .examples([example.clone()])
                .default(Some(example))
                .build(),
        );

        RefOr::T(schema)
    }
}

impl ToSchema for Base64String {}
