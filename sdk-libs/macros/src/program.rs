use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Result};

pub(crate) fn fields(input: &DeriveInput) -> Result<Vec<&syn::Field>> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(fields.named.iter().collect()),
            Fields::Unit => Ok(Vec::new()),
            _ => Err(syn::Error::new_spanned(
                input,
                "program inputs and states use named fields",
            )),
        },
        _ => Err(syn::Error::new_spanned(input, "expected a struct")),
    }
}

pub fn program(input: &DeriveInput) -> Result<TokenStream> {
    let fields = fields(input)?;
    if fields.len() != 2
        || !["private", "public"].iter().all(|name| {
            fields
                .iter()
                .any(|field| field.ident.as_ref().is_some_and(|ident| ident == name))
        })
    {
        return Err(syn::Error::new_spanned(
            input,
            "a program has exactly private and public inputs",
        ));
    }
    let ident = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "a program entry has concrete inputs; generic types may be nested in them",
        ));
    }
    let name = snake_case(&ident.to_string());
    let mut rust_type = format!("circuits::{ident}");
    let mut has_path = false;
    let mut raw = false;
    for attr in input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("zk_program"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("raw_client") {
                if raw {
                    return Err(meta.error("raw_client is given more than once"));
                }
                raw = true;
                return Ok(());
            }
            if meta.path.is_ident("client") {
                return Err(meta.error("client conversions are derived from the input structs"));
            }
            if !meta.path.is_ident("path") {
                return Err(meta.error("expected path or raw_client"));
            }
            if has_path {
                return Err(meta.error("path is given more than once"));
            }
            has_path = true;
            let path: syn::LitStr = meta.value()?.parse()?;
            let _: syn::Path = path.parse()?;
            rust_type = path.value();
            Ok(())
        })?;
    }
    let export = format_ident!("__zk_export_{name}");
    let module = format_ident!("__zk_client_{name}");
    let transaction_js = format!("{}Transaction", lower_first(&ident.to_string()));
    let private = &fields
        .iter()
        .find(|field| field.ident.as_ref().is_some_and(|ident| ident == "private"))
        .unwrap()
        .ty;
    let public_field = fields
        .iter()
        .find(|field| field.ident.as_ref().is_some_and(|ident| ident == "public"))
        .unwrap();
    let public = &public_field.ty;
    let client = if raw {
        quote! {
            ::spr_program::__zk_wasm! {
                mod #module {
                    use ::spr_program::__private::wasm_bindgen;
                    use wasm_bindgen::prelude::*;
                    #[wasm_bindgen(wasm_bindgen = ::spr_program::__private::wasm_bindgen, js_name = #transaction_js)]
                    pub fn transaction(
                        #[wasm_bindgen(unchecked_param_type = "Record<string, unknown>")] inputs: JsValue,
                        #[wasm_bindgen(unchecked_param_type = "ProgramInputRecords")] records: JsValue,
                        sender: &[u8], payer: &str)
                        -> Result<::spr_program::__private::Ts<::spr_program::wasm::ProgramTransaction>, JsValue>
                    {
                        ::spr_program::wasm::program_transaction::<super::#ident>(inputs, records, sender, payer, |program| program.execute())
                    }
                }
            }
        }
    } else {
        let private_ts = crate::client_inputs::client_name(private)?;
        let public_ts = crate::client_inputs::client_name(public)?;
        let client = format_ident!("{ident}Client");
        let private_alias = format_ident!("__{ident}Private");
        let public_alias = format_ident!("__{ident}Public");
        let visibility = &input.vis;
        quote! {
            ::spr_program::__zk_client! {
                #[doc(hidden)] type #private_alias = #private;
                #[doc(hidden)] type #public_alias = #public;
                #visibility use #module::#ident as #client;
                #[doc(hidden)]
                mod #module {
                    #[cfg_attr(feature = "wasm", derive(::serde::Deserialize, ::tsify::Tsify),
                        serde(rename_all = "camelCase", deny_unknown_fields))]
                    pub struct #ident {
                        #[cfg_attr(feature = "wasm", tsify(type = #private_ts), serde(deserialize_with = "::spr_program::wasm::deserialize_client_input"))]
                        pub private: <super::#private_alias as ::spr_program::ClientInputs>::Client,
                        #[cfg_attr(feature = "wasm", tsify(type = #public_ts), serde(deserialize_with = "::spr_program::wasm::deserialize_client_input"))]
                        pub public: <super::#public_alias as ::spr_program::ClientInputs>::Client,
                    }
                    impl #ident {
                        pub fn prepare(self, sender: &::spr_program::__private::NativeShieldedAddress,
                            payer: ::spr_program::__private::Address) -> Result<::spr_program::ProgramTransaction, ::spr_program::ClientError> {
                            let mut records = ::spr_program::InputRecords::new();
                            records.address(sender)?;
                            let program = super::#ident {
                                private: <super::#private_alias as ::spr_program::ClientInputs>::from_client(self.private, &mut records)?,
                                public: <super::#public_alias as ::spr_program::ClientInputs>::from_client(self.public, &mut records)?,
                            };
                            records.create_program_transaction(&program, program.execute().map_err(::spr_program::__private::client_error)?, sender, payer)
                        }
                    }
                    ::spr_program::__zk_wasm! {
                        use ::spr_program::__private::wasm_bindgen;
                        use wasm_bindgen::prelude::*;
                        #[wasm_bindgen(wasm_bindgen = ::spr_program::__private::wasm_bindgen, js_name = #transaction_js)]
                        pub fn transaction(inputs: ::spr_program::__private::Ts<#ident>, sender: &[u8], payer: &str)
                            -> Result<::spr_program::__private::Ts<::spr_program::wasm::ProgramTransaction>, JsValue> {
                            ::spr_program::wasm::prepare_program_transaction(inputs, sender, payer, |inputs, sender, payer| inputs.prepare(sender, payer))
                        }
                    }
                }
            }
        }
    };
    Ok(quote! {
        #client
        ::spr_program::__zk_export! {
            #[test]
            fn #export() {
                ::spr_program::build::export_program(#name, #rust_type,
                    <#public as ::spr_program::build::PublicInputLayout>::layout());
            }
        }
    })
}

fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i != 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    chars
        .next()
        .map(|first| first.to_lowercase().chain(chars).collect())
        .unwrap_or_default()
}

pub fn public(input: &DeriveInput) -> Result<TokenStream> {
    let fields = fields(input)?;
    if fields.len() > 11 {
        return Err(syn::Error::new_spanned(
            input,
            "public fields and the transaction commitment fit in twelve Poseidon inputs",
        ));
    }
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let hashes = fields.iter().map(|field| {
        let field = &field.ident;
        quote!(::spr_program::circuit::DataHash::hash(&self.#field)?)
    });
    let layout = fields.iter().map(|field| {
        let name = field.ident.as_ref().unwrap().to_string();
        let ty = &field.ty;
        quote!((#name, <#ty as ::spr_program::build::PublicField>::kind()))
    });
    let client = if input.generics.params.is_empty() {
        crate::client_inputs::expand(input)?
    } else {
        TokenStream::new()
    };
    Ok(quote! {
        #client
        impl #impl_generics ::spr_program::circuit::PublicInputs for #ident #ty_generics #where_clause {
            fn hash(&self, transaction_hash: &::spr_program::Field)
                -> Result<::spr_program::Field, ::spr_program::CircuitError>
            {
                ::spr_program::poseidon(&[#(#hashes,)* *transaction_hash])
            }
        }
        ::spr_program::__zk_export! {
            impl #impl_generics ::spr_program::build::PublicInputLayout for #ident #ty_generics #where_clause {
                fn layout() -> ::spr_program::__private::Vec<(&'static str, ::spr_program::build::PublicFieldKind)> {
                    ::spr_program::__private::vec![#(#layout),*]
                }
            }
        }
    })
}

pub fn state(input: &DeriveInput) -> Result<TokenStream> {
    let fields = fields(input)?;
    if fields.len() > 11 {
        return Err(syn::Error::new_spanned(
            input,
            "state fields and the discriminator fit in twelve Poseidon inputs",
        ));
    }
    let codec = crate::encryption_codec::generate(input)?;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let discriminator = spr_hasher::state_discriminator(&ident.to_string())
        .map_err(|error| syn::Error::new_spanned(input, error.to_string()))?;
    let tag = u64::from_be_bytes(discriminator);
    let module = format_ident!("__zk_state_{}", snake_case(&ident.to_string()));
    let data_js = format!("{}DataUtxo", lower_first(&ident.to_string()));
    // Tsify's ABI descriptor erases generic arguments; the Rust return value is
    // still DataUtxo<State>, so retain that concrete type in the declaration.
    let data_type = format!("DataUtxo<{ident}>");
    let hashes = fields.iter().map(|field| {
        let field = &field.ident;
        quote!(::spr_program::circuit::DataHash::hash(&self.#field)?)
    });
    let wasm_state = if input.generics.params.is_empty() {
        quote! {
        ::spr_program::__zk_wasm! {
            #[doc(hidden)]
            mod #module {
                use ::spr_program::__private::wasm_bindgen;
                use wasm_bindgen::prelude::*;
                #[wasm_bindgen(wasm_bindgen = ::spr_program::__private::wasm_bindgen, js_name = #data_js, unchecked_return_type = #data_type)]
                pub fn data_utxo(utxo: ::spr_program::__private::Ts<::spr_program::wasm::WalletUtxo>) -> Result<::spr_program::__private::Ts<::spr_program::wasm::DataUtxo<super::#ident>>, JsValue> {
                    ::spr_program::wasm::data_utxo::<super::#ident>(utxo)
                }
            }
        }
        }
    } else {
        TokenStream::new()
    };
    Ok(quote! {
        impl #impl_generics ::spr_program::hasher::Discriminator for #ident #ty_generics #where_clause {
            const DISCRIMINATOR: [u8; 8] = [#(#discriminator),*];
        }
        impl #impl_generics ::spr_program::circuit::DataHash for #ident #ty_generics #where_clause {
            fn hash(&self) -> Result<::spr_program::Field, ::spr_program::CircuitError> {
                ::spr_program::poseidon(&[::spr_program::Field::from(#tag), #(#hashes),*])
            }
        }
        #codec
        impl #impl_generics ::spr_program::circuit::UtxoData for #ident #ty_generics #where_clause {}
        #wasm_state
        #[cfg(not(xark))]
        impl #impl_generics ::spr_program::hasher::DataHasher for #ident #ty_generics #where_clause {
            fn hash(&self) -> Result<[u8; 32], ::spr_program::hasher::HasherError> {
                let hash = <Self as ::spr_program::circuit::DataHash>::hash(self)
                    .map_err(|_| ::spr_program::hasher::HasherError::InvalidNumFields)?;
                Ok(::spr_program::to_bytes(&hash))
            }
        }
    })
}

#[cfg(test)]
#[path = "program_tests.rs"]
mod tests;
