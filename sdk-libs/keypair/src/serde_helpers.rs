pub use serde_bytes as bytes;

pub mod address {
    use core::str::FromStr;

    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use solana_address::Address;

    pub fn serialize<S: Serializer>(address: &Address, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(address)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Address, D::Error> {
        let text = String::deserialize(deserializer)?;
        Address::from_str(&text).map_err(D::Error::custom)
    }
}

pub mod option_address {
    use core::str::FromStr;

    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use solana_address::Address;

    pub fn serialize<S: Serializer>(
        address: &Option<Address>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match address {
            Some(address) => serializer.collect_str(address),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Address>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| Address::from_str(&text).map_err(D::Error::custom))
            .transpose()
    }
}
