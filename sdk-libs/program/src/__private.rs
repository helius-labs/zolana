#[cfg(feature = "serde")]
pub use zolana_zk_dsl::__private::*;

pub use crate::verifier_glue::render_verifier;

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
// zolana-zk-dsl defines the same gates on its own features for standalone
// circuits. A ZK program's derives resolve to these, gated on this crate's
// features, which also enable the matching wallet type serde impls.
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
