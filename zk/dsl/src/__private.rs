#[cfg(feature = "serde")]
pub use serde;
#[cfg(feature = "serde")]
pub use serde_bytes as bytes;
#[cfg(feature = "tsify")]
pub use tsify;
#[cfg(feature = "tsify")]
pub use wasm_bindgen;

#[cfg(feature = "serde")]
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

#[cfg(feature = "serde")]
pub mod array {
    use core::{fmt, marker::PhantomData};

    use serde::{
        de::{Error, SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserialize, Deserializer, Serialize, Serializer,
    };

    pub fn serialize<S: Serializer, T: Serialize, const N: usize>(
        array: &[T; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(N)?;
        for element in array {
            tuple.serialize_element(element)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[T; N], D::Error> {
        deserializer.deserialize_tuple(N, ArrayVisitor(PhantomData))
    }

    struct ArrayVisitor<T, const N: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for ArrayVisitor<T, N> {
        type Value = [T; N];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "an array of {N} elements")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[T; N], A::Error> {
            let mut elements = Vec::with_capacity(N);
            while let Some(element) = seq.next_element()? {
                if elements.len() == N {
                    return Err(A::Error::invalid_length(N + 1, &self));
                }
                elements.push(element);
            }
            elements
                .try_into()
                .map_err(|elements: Vec<T>| A::Error::invalid_length(elements.len(), &self))
        }
    }
}

// The cfg is evaluated in this crate, not in the consuming program.
macro_rules! feature_macro {
    ($name:ident, $feature:literal, $d:tt, { $($definition:tt)* }) => {
        #[cfg(feature = $feature)]
        #[doc(hidden)]
        #[macro_export]
        macro_rules! $name { $($definition)* }

        #[cfg(not(feature = $feature))]
        #[doc(hidden)]
        #[macro_export]
        macro_rules! $name { ($d($d item:tt)*) => {}; }
    };
}

feature_macro!(__proof_input_serde, "serde", $, {
    ($($item:tt)*) => { $($item)* };
});
feature_macro!(__proof_input_tsify, "tsify", $, {
    ($($item:tt)*) => { $($item)* };
});

#[cfg(feature = "tsify")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const FIELD_TYPE: &str = "export type Field = Uint8Array;";
