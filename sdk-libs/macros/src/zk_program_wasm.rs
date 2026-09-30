use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

use crate::{
    paths,
    shape::{snake_case, Shape},
};

pub(crate) fn generate(input: &DeriveInput, shape: &Shape) -> TokenStream {
    if !input.generics.params.is_empty() || !shape.is_program() {
        return TokenStream::new();
    }

    let ident = &input.ident;
    let name = ident.to_string();
    let module = format_ident!("__zk_program_wasm_{}", snake_case(&name));
    let transaction = format_ident!("{}_transaction", snake_case(&name));
    let transaction_js = format!("{}Transaction", lower_first(&name));
    let prover = format_ident!("{}Prover", ident);
    let wasm = paths::wasm();

    quote! {
        ::zolana_program::__zk_program_wasm! {
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

                ::zolana_program::__zk_program_wasm_prover!(#prover, super::#ident);
            }
        }
    }
}

pub(crate) fn data_utxo(input: &DeriveInput) -> TokenStream {
    if !input.generics.params.is_empty() {
        return TokenStream::new();
    }

    let ident = &input.ident;
    let name = ident.to_string();
    let module = format_ident!("__zk_program_wasm_data_{}", snake_case(&name));
    let data_utxo = format_ident!("{}_data_utxo", snake_case(&name));
    let data_utxo_js = format!("{}DataUtxo", lower_first(&name));
    let data_utxo_type = format!("DataUtxo<{name}>");
    let wasm = paths::wasm();

    quote! {
        ::zolana_program::__zk_program_wasm! {
            #[doc(hidden)]
            mod #module {
                use #wasm::__private::wasm_bindgen;
                use wasm_bindgen::prelude::*;

                #[wasm_bindgen(
                    wasm_bindgen = #wasm::__private::wasm_bindgen,
                    js_name = #data_utxo_js,
                    unchecked_return_type = #data_utxo_type
                )]
                pub fn #data_utxo(
                    #[wasm_bindgen(unchecked_param_type = "WalletUtxo")] utxo: JsValue,
                ) -> ::core::result::Result<JsValue, JsValue> {
                    #wasm::data_utxo::<super::#ident>(utxo)
                }
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
