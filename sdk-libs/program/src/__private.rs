#[cfg(feature = "serde")]
pub use serde;
#[cfg(feature = "tsify")]
pub use tsify;
#[cfg(feature = "tsify")]
pub use wasm_bindgen;
#[cfg(feature = "serde")]
pub use zolana_keypair::serde_helpers::{address, bytes};

pub use crate::verifier_glue::render_verifier;

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
pub fn write_r1cs<P: crate::ZkProgram>(
    name: &str,
    layout: &[(&'static str, crate::PublicFieldKind)],
) {
    let dir = std::path::PathBuf::from(
        std::env::var_os("ZOLANA_ZK_R1CS_OUT")
            .unwrap_or_else(|| panic!("ZOLANA_ZK_R1CS_OUT names no directory for {name}.r1cs")),
    );
    let r1cs = P::export_r1cs().unwrap_or_else(|error| panic!("{name}: {error}"));
    let path = dir.join(format!("{name}.r1cs"));
    std::fs::write(&path, r1cs).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    println!("zolana-zk-r1cs: {}", path.display());
    let verifier = dir.join(format!("{name}.verifier.rs"));
    std::fs::write(&verifier, render_verifier(name, layout))
        .unwrap_or_else(|error| panic!("{}: {error}", verifier.display()));
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

feature_macro!(__zk_program_r1cs, "r1cs-export", $, {
    ($($item:tt)*) => { $($item)* };
});
feature_macro!(__zk_program_wasm, "wasm", $, {
    ($($item:tt)*) => { $($item)* };
});
feature_macro!(__proof_input_serde, "serde", $, {
    ($($item:tt)*) => { $($item)* };
});
feature_macro!(__proof_input_tsify, "tsify", $, {
    ($($item:tt)*) => { $($item)* };
});

feature_macro!(__zk_program_wasm_prover, "wasm-prover", $, {
    ($prover:ident, $program:ty) => {
        #[wasm_bindgen(wasm_bindgen = $crate::__private::wasm_bindgen)]
        pub struct $prover($crate::Groth16Prover<$program>);

        #[wasm_bindgen]
        impl $prover {
            #[wasm_bindgen(js_name = fromKey)]
            pub fn from_key(
                #[wasm_bindgen(js_name = provingKey)] proving_key: &[u8],
                #[wasm_bindgen(js_name = expectedSha256)] expected_sha256: &[u8],
            ) -> ::core::result::Result<$prover, $crate::__private::wasm_bindgen::JsValue>
            {
                $crate::wasm::prover_from_key::<$program>(proving_key, expected_sha256).map(Self)
            }

            #[wasm_bindgen(js_name = fromZkey)]
            pub fn from_zkey(
                zkey: &[u8],
            ) -> ::core::result::Result<$prover, $crate::__private::wasm_bindgen::JsValue>
            {
                $crate::wasm::prover_from_zkey::<$program>(zkey).map(Self)
            }

            #[wasm_bindgen(unchecked_return_type = "ProgramProof")]
            pub fn prove(
                &self,
                #[wasm_bindgen(js_name = proofInputs)] proof_inputs: &[u8],
            ) -> ::core::result::Result<
                $crate::__private::wasm_bindgen::JsValue,
                $crate::__private::wasm_bindgen::JsValue,
            > {
                $crate::wasm::prove(&self.0, proof_inputs)
            }
        }
    };
});

#[cfg(feature = "tsify")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const FIELD_TYPE: &str = "export type Field = Uint8Array;";
