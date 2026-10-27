use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Result};

fn fields(input: &DeriveInput) -> Result<Vec<&syn::Field>> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(fields.named.iter().collect()),
            Fields::Unit => Ok(Vec::new()),
            _ => Err(syn::Error::new_spanned(input, "program inputs and states use named fields")),
        },
        _ => Err(syn::Error::new_spanned(input, "expected a struct")),
    }
}

pub fn program(input: &DeriveInput) -> Result<TokenStream> {
    let fields = fields(input)?;
    if fields.len() != 2 || !["private", "public"].iter().all(|name| fields.iter().any(|field| field.ident.as_ref().is_some_and(|ident| ident == name))) {
        return Err(syn::Error::new_spanned(input, "a program has exactly private and public inputs"));
    }
    let ident = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(&input.generics, "a program entry has concrete inputs; generic types may be nested in them"));
    }
    let name = snake_case(&ident.to_string());
    let mut rust_type = format!("circuits::{ident}");
    for attr in input.attrs.iter().filter(|attr| attr.path().is_ident("zk_program")) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("path") { return Err(meta.error("expected path = \"public::Type\"")); }
            let path: syn::LitStr = meta.value()?.parse()?;
            let _: syn::Path = path.parse()?;
            rust_type = path.value();
            Ok(())
        })?;
    }
    let export = format_ident!("__zk_export_{name}");
    let wasm_module = format_ident!("__zk_wasm_{name}");
    let transaction_js = format!("{}Transaction", lower_first(&ident.to_string()));
    let public = &fields.iter().find(|field| field.ident.as_ref().is_some_and(|ident| ident == "public")).unwrap().ty;
    Ok(quote! {
        ::zolana_program::__zk_wasm! {
            #[doc(hidden)]
            mod #wasm_module {
                use ::zolana_program::__private::wasm_bindgen;
                use wasm_bindgen::prelude::*;
                #[wasm_bindgen(wasm_bindgen = ::zolana_program::__private::wasm_bindgen, js_name = #transaction_js)]
                pub fn transaction(inputs: JsValue, records: JsValue, sender: &[u8], payer: &str) -> Result<JsValue, JsValue> {
                    ::zolana_program::wasm::program_transaction::<super::#ident>(inputs, records, sender, payer, |program| program.execute())
                }
            }
        }
        ::zolana_program::__zk_export! {
            #[test]
            fn #export() {
                ::zolana_program::build::export_program(#name, #rust_type,
                    <#public as ::zolana_program::build::PublicInputLayout>::layout());
            }
        }
    })
}

fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i != 0 { out.push('_'); }
        out.extend(c.to_lowercase());
    }
    out
}

fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    chars.next().map(|first| first.to_lowercase().chain(chars).collect()).unwrap_or_default()
}

pub fn public(input: &DeriveInput) -> Result<TokenStream> {
    let fields = fields(input)?;
    if fields.len() > 11 { return Err(syn::Error::new_spanned(input, "public fields and the transaction commitment fit in twelve Poseidon inputs")); }
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let hashes = fields.iter().map(|field| {
        let field = &field.ident;
        quote!(::zolana_program::circuit::DataHash::hash(&self.#field)?)
    });
    let layout = fields.iter().map(|field| {
        let name = field.ident.as_ref().unwrap().to_string();
        let ty = &field.ty;
        quote!((#name, <#ty as ::zolana_program::build::PublicField>::kind()))
    });
    Ok(quote! {
        impl #impl_generics ::zolana_program::circuit::PublicInputs for #ident #ty_generics #where_clause {
            fn hash(&self, transaction_hash: &::zolana_program::Field)
                -> Result<::zolana_program::Field, ::zolana_program::CircuitError>
            {
                ::zolana_program::poseidon(&[#(#hashes,)* *transaction_hash])
            }
        }
        ::zolana_program::__zk_export! {
            impl #impl_generics ::zolana_program::build::PublicInputLayout for #ident #ty_generics #where_clause {
                fn layout() -> Vec<(&'static str, ::zolana_program::build::PublicFieldKind)> {
                    vec![#(#layout),*]
                }
            }
        }
    })
}

pub fn state(input: &DeriveInput) -> Result<TokenStream> {
    let fields = fields(input)?;
    if fields.len() > 11 { return Err(syn::Error::new_spanned(input, "state fields and the discriminator fit in twelve Poseidon inputs")); }
    let codec = crate::encryption_codec::generate(input)?;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let discriminator = zolana_hasher::state_discriminator(&ident.to_string())
        .map_err(|error| syn::Error::new_spanned(input, error.to_string()))?;
    let tag = u64::from_be_bytes(discriminator);
    let module = format_ident!("__zk_state_{}", snake_case(&ident.to_string()));
    let data_js = format!("{}DataUtxo", lower_first(&ident.to_string()));
    let hashes = fields.iter().map(|field| {
        let field = &field.ident;
        quote!(::zolana_program::circuit::DataHash::hash(&self.#field)?)
    });
    Ok(quote! {
        impl #impl_generics ::zolana_program::hasher::Discriminator for #ident #ty_generics #where_clause {
            const DISCRIMINATOR: [u8; 8] = [#(#discriminator),*];
        }
        impl #impl_generics ::zolana_program::circuit::DataHash for #ident #ty_generics #where_clause {
            fn hash(&self) -> Result<::zolana_program::Field, ::zolana_program::CircuitError> {
                ::zolana_program::poseidon(&[::zolana_program::Field::from(#tag), #(#hashes),*])
            }
        }
        #codec
        impl #impl_generics ::zolana_program::circuit::UtxoData for #ident #ty_generics #where_clause {}
        ::zolana_program::__zk_wasm! {
            #[doc(hidden)]
            mod #module {
                use ::zolana_program::__private::wasm_bindgen;
                use wasm_bindgen::prelude::*;
                #[wasm_bindgen(wasm_bindgen = ::zolana_program::__private::wasm_bindgen, js_name = #data_js)]
                pub fn data_utxo(utxo: JsValue) -> Result<JsValue, JsValue> {
                    ::zolana_program::wasm::data_utxo::<super::#ident>(utxo)
                }
            }
        }
        #[cfg(not(xark))]
        impl #impl_generics ::zolana_program::hasher::DataHasher for #ident #ty_generics #where_clause {
            fn hash(&self) -> Result<[u8; 32], ::zolana_program::hasher::HasherError> {
                let hash = <Self as ::zolana_program::circuit::DataHash>::hash(self)
                    .map_err(|_| ::zolana_program::hasher::HasherError::InvalidNumFields)?;
                Ok(::zolana_program::to_bytes(&hash))
            }
        }
    })
}
