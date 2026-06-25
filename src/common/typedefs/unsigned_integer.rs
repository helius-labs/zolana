use serde::de::Visitor;
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use serde_json::Number;
use std::fmt;
use utoipa::{
    openapi::{
        schema::{ObjectBuilder, Schema, SchemaType, Type},
        KnownFormat, RefOr, SchemaFormat,
    },
    PartialSchema, ToSchema,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default, Copy, PartialOrd, Ord)]
#[serde(transparent)]
pub struct UnsignedInteger(pub u64);

impl PartialSchema for UnsignedInteger {
    fn schema() -> RefOr<Schema> {
        let example = serde_json::Value::Number(Number::from(100));
        let schema = Schema::Object(
            ObjectBuilder::new()
                .schema_type(SchemaType::new(Type::Integer))
                .default(Some(example.clone()))
                .examples([example])
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::UInt64)))
                .build(),
        );
        RefOr::T(schema)
    }
}

impl ToSchema for UnsignedInteger {}

impl<'de> Deserialize<'de> for UnsignedInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UnsignedIntegerVisitor;

        impl<'de> Visitor<'de> for UnsignedIntegerVisitor {
            type Value = UnsignedInteger;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned integer or string containing an unsigned integer")
            }

            fn visit_u64<E>(self, value: u64) -> Result<UnsignedInteger, E>
            where
                E: Error,
            {
                Ok(UnsignedInteger(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<UnsignedInteger, E>
            where
                E: Error,
            {
                value
                    .parse::<u64>()
                    .map(UnsignedInteger)
                    .map_err(|e| Error::custom(format!("Invalid unsigned integer value: {}", e)))
            }
        }

        deserializer.deserialize_any(UnsignedIntegerVisitor)
    }
}

impl borsh::BorshDeserialize for UnsignedInteger {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, std::io::Error> {
        borsh::BorshDeserialize::deserialize(buf).map(UnsignedInteger)
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        borsh::BorshDeserialize::deserialize_reader(reader).map(UnsignedInteger)
    }
}

impl borsh::BorshSerialize for UnsignedInteger {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        borsh::BorshSerialize::serialize(&self.0, writer)
    }
}
