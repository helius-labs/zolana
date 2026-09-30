#[cfg(feature = "serde")]
pub use serde;
#[cfg(feature = "tsify")]
pub use tsify;
#[cfg(feature = "tsify")]
pub use wasm_bindgen;
#[cfg(feature = "serde")]
pub use zolana_keypair::serde_helpers::{address, bytes};

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

#[cfg(feature = "r1cs-export")]
pub fn write_r1cs<P: crate::ZkProgram>(name: &str) {
    let dir = std::path::PathBuf::from(
        std::env::var_os("ZOLANA_ZK_R1CS_OUT")
            .unwrap_or_else(|| panic!("ZOLANA_ZK_R1CS_OUT names no directory for {name}.r1cs")),
    );
    let r1cs = P::export_r1cs().unwrap_or_else(|error| panic!("{name}: {error}"));
    let path = dir.join(format!("{name}.r1cs"));
    std::fs::write(&path, r1cs).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    println!("zolana-zk-r1cs: {}", path.display());
}

#[cfg(feature = "r1cs-export")]
#[doc(hidden)]
#[macro_export]
macro_rules! __zk_program_r1cs {
    ($($item:tt)*) => {
        $($item)*
    };
}

#[cfg(not(feature = "r1cs-export"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __zk_program_r1cs {
    ($($item:tt)*) => {};
}

#[cfg(feature = "tsify")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const FIELD_TYPE: &'static str = "export type Field = Uint8Array;";

#[cfg(feature = "wasm")]
#[doc(hidden)]
#[macro_export]
macro_rules! __zk_program_wasm {
    ($($item:tt)*) => {
        $($item)*
    };
}

#[cfg(not(feature = "wasm"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __zk_program_wasm {
    ($($item:tt)*) => {};
}

#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! __proof_input_serde {
    ($($item:tt)*) => {
        $($item)*
    };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __proof_input_serde {
    ($($item:tt)*) => {};
}

#[cfg(feature = "tsify")]
#[doc(hidden)]
#[macro_export]
macro_rules! __proof_input_tsify {
    ($($item:tt)*) => {
        $($item)*
    };
}

#[cfg(not(feature = "tsify"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __proof_input_tsify {
    ($($item:tt)*) => {};
}
