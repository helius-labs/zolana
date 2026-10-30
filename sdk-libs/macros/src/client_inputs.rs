use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, GenericArgument, PathArguments, Type};

use crate::program::fields;

pub fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "client input declarations use concrete types",
        ));
    }
    let fields = fields(input)?;
    let name = &input.ident;
    let view = format_ident!("{name}Client");
    let visibility = &input.vis;
    let mut client_fields = Vec::new();
    let mut conversions = Vec::new();
    let mut identity_fields = Some(Vec::new());
    for field in fields {
        let name = field.ident.as_ref().unwrap();
        let ty = &field.ty;
        if let Some(attribute) = field
            .attrs
            .iter()
            .find(|attribute| attribute.path().is_ident("client"))
        {
            return Err(syn::Error::new_spanned(
                attribute,
                "client conversion is automatic; remove the client attribute",
            ));
        }
        let value = quote!(client.#name);
        let (client_type, converted, ts, kind) = mapped(ty, value)?;
        if matches!(kind, Conversion::Identity) {
            if let Some(fields) = &mut identity_fields {
                fields.push(quote!(#name: native.#name));
            }
        } else {
            identity_fields = None;
        }
        let ts = ts.map(|ts| quote!(#[cfg_attr(feature = "wasm", tsify(type = #ts))]));
        let nested = matches!(kind, Conversion::Nested).then(|| quote!(
            #[cfg_attr(feature = "wasm", serde(deserialize_with = "::spr_program::wasm::deserialize_client_input"))]
        ));
        client_fields.push(quote!(#ts #nested pub #name: #client_type));
        conversions.push(quote!(#name: #converted));
    }
    let default = client_fields.is_empty().then(|| quote!(#[derive(Default)]));
    let from_native = identity_fields.map(|fields| {
        quote! {
            impl ::core::convert::From<#name> for #view {
                fn from(native: #name) -> Self { let _ = &native; Self { #(#fields,)* } }
            }
        }
    });
    Ok(quote! {
        ::spr_program::__zk_client! {
            #default
            #[cfg_attr(feature = "wasm", derive(::serde::Deserialize, ::tsify::Tsify),
                serde(rename_all = "camelCase", deny_unknown_fields), tsify(large_number_types_as_bigints))]
            #visibility struct #view { #(#client_fields,)* }
            #from_native
            impl ::spr_program::ClientInputs for #name {
                type Client = #view;
                fn from_client(client: Self::Client, records: &mut ::spr_program::InputRecords)
                    -> Result<Self, ::spr_program::ClientError>
                {
                    let _ = (&client, &records);
                    Ok(Self { #(#conversions,)* })
                }
            }
        }
    })
}

pub fn client_name(ty: &Type) -> syn::Result<String> {
    let Type::Path(path) = ty else {
        return Err(syn::Error::new_spanned(ty, "expected a named input type"));
    };
    let Some(segment) = path.path.segments.last() else {
        return Err(syn::Error::new_spanned(ty, "expected a named input type"));
    };
    Ok(format!("{}Client", segment.ident))
}

enum Conversion {
    Identity,
    Converted,
    Nested,
}

fn mapped(
    ty: &Type,
    value: TokenStream,
) -> syn::Result<(TokenStream, TokenStream, Option<String>, Conversion)> {
    let Type::Path(path) = ty else {
        return Ok((quote!(#ty), value, None, Conversion::Identity));
    };
    let segment = path.path.segments.last().unwrap();
    Ok(match segment.ident.to_string().as_str() {
        "TxContext" => (
            quote!(::spr_program::TransactionOptions),
            quote!(#value.into_context()?),
            Some("TransactionOptions".into()),
            Conversion::Converted,
        ),
        "Utxo" => (
            quote!(::spr_program::__private::WalletUtxo),
            quote!(records.utxo(&#value)?),
            Some("WalletUtxo".into()),
            Conversion::Converted,
        ),
        "ShieldedAddress" => (
            quote!(::spr_program::__private::NativeShieldedAddress),
            quote!(records.address(&#value)?),
            Some("Uint8Array".into()),
            Conversion::Converted,
        ),
        "Field" => (
            quote!(::spr_program::__private::String),
            quote!(::spr_program::from_decimal(&#value).map_err(::spr_program::__private::client_error)?),
            None,
            Conversion::Converted,
        ),
        "ArrayVec" => {
            let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
                return Err(syn::Error::new_spanned(
                    ty,
                    "expected ArrayVec<Item, CAPACITY>",
                ));
            };
            let mut arguments = arguments.args.iter();
            let (Some(GenericArgument::Type(item)), Some(capacity), None) =
                (arguments.next(), arguments.next(), arguments.next())
            else {
                return Err(syn::Error::new_spanned(
                    ty,
                    "expected ArrayVec<Item, CAPACITY>",
                ));
            };
            if matches!(item, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Utxo"))
            {
                (
                    quote!(
                        ::spr_program::__private::Vec<::spr_program::__private::WalletUtxo>
                    ),
                    quote!(records.utxos::<#capacity>(&#value)?),
                    Some("WalletUtxo[]".into()),
                    Conversion::Converted,
                )
            } else {
                (
                    quote!(::spr_program::__private::Vec<#item>),
                    quote!(::spr_program::InputRecords::bounded::<_, #capacity>(#value)?),
                    None,
                    Conversion::Converted,
                )
            }
        }
        "bool" | "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64"
        | "i128" | "isize" | "String" | "UtxoOwner" | "SigningPubkey" => {
            (quote!(#ty), value, None, Conversion::Identity)
        }
        _ => (
            quote!(<#ty as ::spr_program::ClientInputs>::Client),
            quote!(<#ty as ::spr_program::ClientInputs>::from_client(#value, records)?),
            Some(client_name(ty)?),
            Conversion::Nested,
        ),
    })
}

#[cfg(test)]
#[path = "client_inputs_tests.rs"]
mod tests;
