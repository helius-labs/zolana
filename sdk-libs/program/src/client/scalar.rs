//! Canonical hash and blinding inputs, represented as bytes in application APIs.
use crate::{
    circuit::CircuitVar,
    conversion::{field, to_bytes, Allocator, FromCircuit, Placeholder, ProofInput},
    CircuitError, PublicField, PublicFieldKind, PublicHashField,
};

macro_rules! scalar_input {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Accepts exactly one canonical, big-endian BN254 scalar.
            /// Values outside the scalar field are rejected rather than reduced.
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CircuitError> {
                field(&bytes, $description)?;
                Ok(Self(bytes))
            }

            pub const fn to_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl ProofInput for $name {
            type Circuit = CircuitVar;

            fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, CircuitError> {
                field(&self.0, $description)?.instantiate(allocator)
            }
        }

        impl FromCircuit for $name {
            fn from_circuit(value: &CircuitVar) -> Result<Self, CircuitError> {
                Ok(Self(to_bytes(value)?))
            }
        }

        impl Placeholder for $name {
            fn placeholder() -> Result<Self, CircuitError> {
                Ok(Self::default())
            }
        }

        impl PublicField for $name {
            fn kind() -> PublicFieldKind {
                PublicFieldKind::Hash
            }
        }

        impl PublicHashField for $name {}

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                zolana_zk_dsl::__private::bytes::serialize(&self.0, serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = zolana_zk_dsl::__private::bytes::deserialize(deserializer)?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}

scalar_input!(
    Hash,
    "A commitment or hash, carried as 32 canonical big-endian bytes."
);
scalar_input!(
    Blinding,
    "A private blinding, carried as 32 canonical big-endian bytes."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_blindings_preserve_canonical_scalar_bytes() {
        let mut bytes = [0; 32];
        bytes[31] = 42;
        let hash = Hash::from_bytes(bytes).expect("canonical hash");
        let blinding = Blinding::from_bytes(bytes).expect("canonical blinding");
        assert_eq!((hash.to_bytes(), blinding.to_bytes()), (bytes, bytes));
        let allocator = Allocator::native();
        assert_eq!(
            to_bytes(&hash.instantiate(&allocator).expect("hash input")).expect("hash bytes"),
            bytes
        );
        assert_eq!(
            to_bytes(&blinding.instantiate(&allocator).expect("blinding input"))
                .expect("blinding bytes"),
            bytes
        );
    }

    #[test]
    fn noncanonical_scalars_are_rejected_without_reduction() {
        assert!(Hash::from_bytes([255; 32]).is_err());
        assert!(Blinding::from_bytes([255; 32]).is_err());
    }
}
