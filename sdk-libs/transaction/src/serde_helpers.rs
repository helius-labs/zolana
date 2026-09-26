pub(crate) mod signature {
    use serde::{Deserializer, Serializer};
    use solana_signature::Signature;
    use zolana_keypair::serde_helpers::bytes;

    pub(crate) fn serialize<S: Serializer>(
        signature: &Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        bytes::serialize(&<[u8; 64]>::from(*signature), serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Signature, D::Error> {
        let signature: [u8; 64] = bytes::deserialize(deserializer)?;
        Ok(Signature::from(signature))
    }
}
