use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Error, Result};

use crate::paths;

pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    if !matches!(input.data, Data::Struct(_)) {
        return Err(Error::new_spanned(
            &input.ident,
            "`ZkProgramWasm` derives on the program's input struct",
        ));
    }
    if !input.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &input.generics,
            "`ZkProgramWasm` needs a concrete program; wrap a generic one in a non-generic struct",
        ));
    }

    let ident = &input.ident;
    let name = ident.to_string();
    let module = format_ident!("__zk_program_wasm_{}", snake_case(&name));
    let transaction = format_ident!("{}_transaction", snake_case(&name));
    let transaction_js = format!("{}Transaction", lower_first(&name));
    let prover = format_ident!("{}Prover", ident);
    let wasm = paths::wasm();

    Ok(quote! {
        #[doc(hidden)]
        mod #module {
            use #wasm::__private::wasm_bindgen;
            use wasm_bindgen::prelude::*;

            #[wasm_bindgen(
                wasm_bindgen = #wasm::__private::wasm_bindgen,
                js_name = #transaction_js,
                unchecked_return_type = "ProgramTransaction"
            )]
            pub fn #transaction(
                #[wasm_bindgen(unchecked_param_type = #name)] inputs: JsValue,
                sender: &[u8],
                payer: &str,
            ) -> ::core::result::Result<JsValue, JsValue> {
                #wasm::program_transaction::<super::#ident>(inputs, sender, payer)
            }

            ::zk_program_sdk::__zk_program_wasm_prover!(#prover, super::#ident);
        }
    })
}

fn snake_case(name: &str) -> String {
    let mut snake = String::with_capacity(name.len() + 4);
    for (index, character) in name.char_indices() {
        if character.is_uppercase() {
            if index > 0 {
                snake.push('_');
            }
            snake.extend(character.to_lowercase());
        } else {
            snake.push(character);
        }
    }
    snake
}

fn lower_first(name: &str) -> String {
    let mut characters = name.chars();
    characters
        .next()
        .map(|first| first.to_lowercase().chain(characters).collect())
        .unwrap_or_default()
}
