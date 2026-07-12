use std::str::FromStr;

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use solana_signature::Signature;
use utoipa::{
    openapi::{
        schema::{ObjectBuilder, Schema, Type},
        RefOr,
    },
    PartialSchema, ToSchema,
};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SerializableSignature(pub Signature);

struct Base58Visitor;

impl<'de> Visitor<'de> for Base58Visitor {
    type Value = SerializableSignature;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a base58 encoded string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Signature::from_str(value)
            .map_err(|e| E::custom(e.to_string()))
            .map(SerializableSignature)
    }
}

impl<'de> Deserialize<'de> for SerializableSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Base58Visitor)
    }
}

impl Serialize for SerializableSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let base58_string = bs58::encode(self.0).into_string();
        serializer.serialize_str(&base58_string)
    }
}

impl PartialSchema for SerializableSignature {
    fn schema() -> RefOr<Schema> {
        let example =
            serde_json::Value::String("5J8H5sTvEhnGcB4R8K1n7mfoiWUD9RzPVGES7e3WxC7c".to_string());
        let schema = Schema::Object(
            ObjectBuilder::new()
                .schema_type(Type::String)
                .description(Some("A Solana transaction signature."))
                .examples([example.clone()])
                .default(Some(example))
                .build(),
        );

        RefOr::T(schema)
    }
}

impl ToSchema for SerializableSignature {}
