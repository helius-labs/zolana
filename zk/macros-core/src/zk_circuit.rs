use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, Error, Result};

use crate::{
    proof_input, r1cs_hook,
    shape::{snake_case, Shape},
};

/// `#[derive(ZkCircuit)]`: a circuit with regular public inputs, a struct with
/// exactly the fields `private` and `public`. Emits its proof input, the
/// `<Name>Prover` wasm class and the r1cs export hook whose verifier binds
/// every public field directly.
pub fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    if !shape.is_program() {
        return Err(Error::new_spanned(
            &input.ident,
            "a ZK circuit is a struct with exactly the fields `private` and `public`",
        ));
    }
    let wasm = wasm_prover(input);
    let r1cs = r1cs_hook::generate(
        input,
        &shape,
        &quote!(::zolana_program::__zk_circuit_r1cs),
        &quote!(::zolana_program::__private::write_circuit_r1cs),
    );
    Ok(proof_input::generate_with(
        input,
        &shape,
        quote! {
            #wasm

            #r1cs
        },
    ))
}

/// The JavaScript bindings of a circuit with the zk DSL's `wasm` feature:
/// `<name>ProofInputs`, which builds its proof inputs from its typed inputs,
/// and, with `wasm-prover`, the `<Name>Prover` class.
fn wasm_prover(input: &DeriveInput) -> TokenStream {
    if !input.generics.params.is_empty() {
        return TokenStream::new();
    }
    let ident = &input.ident;
    let name = ident.to_string();
    let snake = snake_case(&name);
    let module = format_ident!("__zk_circuit_wasm_{}", snake);
    let proof_inputs = format_ident!("{}_proof_inputs", snake);
    let proof_inputs_js = format!("{}ProofInputs", lower_first(&name));
    let prover = format_ident!("{}Prover", ident);
    quote! {
        ::zolana_program::__zk_circuit_wasm! {
            #[doc(hidden)]
            mod #module {
                use ::zolana_program::__private::wasm_bindgen;
                use wasm_bindgen::prelude::*;

                #[wasm_bindgen(
                    wasm_bindgen = ::zolana_program::__private::wasm_bindgen,
                    js_name = #proof_inputs_js
                )]
                pub fn #proof_inputs(
                    #[wasm_bindgen(unchecked_param_type = #name)] inputs: JsValue,
                ) -> ::core::result::Result<::std::vec::Vec<u8>, JsValue> {
                    ::zolana_program::wasm::proof_inputs::<super::#ident>(inputs)
                }

                ::zolana_program::__zk_circuit_wasm_prover!(#prover, super::#ident);
            }
        }
    }
}

fn lower_first(name: &str) -> String {
    let mut characters = name.chars();
    characters
        .next()
        .map(|first| first.to_lowercase().chain(characters).collect())
        .unwrap_or_default()
}
