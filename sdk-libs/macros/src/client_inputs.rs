use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::{spanned::Spanned, DeriveInput, GenericArgument, PathArguments, Type};

use crate::program::fields;
use crate::syntax::{last_segment, one_module_down, snake_case, ungroup};

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
    let mut identity_fields = Vec::new();
    let mut all_identity = true;
    let mut errors: Option<syn::Error> = None;
    for field in fields {
        let (name, mapping) = match field_mapping(field) {
            Ok(mapped) => mapped,
            Err(error) => {
                match &mut errors {
                    Some(errors) => errors.combine(error),
                    None => errors = Some(error),
                }
                continue;
            }
        };
        let Mapping {
            client: client_type,
            converted,
            ts,
            deserialize_with,
            identity,
        } = mapping;
        all_identity &= identity;
        identity_fields.push(quote!(#name: native.#name));
        let ts = ts.map(|ts| quote!(#[cfg_attr(feature = "wasm", tsify(type = #ts))]));
        let deserialize_with = deserialize_with
            .map(|path| quote!(#[cfg_attr(feature = "wasm", serde(deserialize_with = #path))]));
        // The view sits in a module below the input's, the conversions beside it.
        let client_type = one_module_down(&syn::parse2(client_type)?, &input.ident);
        client_fields.push(quote!(#ts #deserialize_with pub #name: #client_type));
        conversions.push(quote!(#name: #converted));
    }
    if let Some(errors) = errors {
        return Err(errors);
    }
    let default = client_fields.is_empty().then(|| quote!(#[derive(Default)]));
    let from_native = all_identity.then(|| {
        quote! {
            impl ::core::convert::From<#name> for #view {
                fn from(native: #name) -> Self { let _ = &native; Self { #(#identity_fields,)* } }
            }
        }
    });
    // The view lives in a hidden module that imports serde, tsify and
    // wasm-bindgen from spr-program, so the program crate needs none of them.
    // The glob import resolves the field types as the input's module does.
    let module = format_ident!("__zk_inputs_{}", snake_case(&name.to_string()));
    Ok(quote! {
        ::spr_program::__zk_client! {
            #visibility use #module::#view;
            #[doc(hidden)]
            mod #module {
                #[allow(unused_imports)]
                use super::*;
                #[cfg(feature = "wasm")]
                use ::spr_program::__private::{serde, tsify, wasm_bindgen};
                #default
                #[cfg_attr(feature = "wasm", derive(serde::Deserialize, tsify::Tsify),
                    serde(crate = "::spr_program::__private::serde", rename_all = "camelCase", deny_unknown_fields),
                    tsify(large_number_types_as_bigints))]
                pub struct #view { #(#client_fields,)* }
            }
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

fn field_mapping(field: &syn::Field) -> syn::Result<(&syn::Ident, Mapping)> {
    let name = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new_spanned(field, "expected a named field"))?;
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
    let kind = classify(&field.ty)?;
    Ok((name, mapping(kind, &field.ty, name)))
}

/// The TypeScript name of the client view of a nested input type.
pub fn client_name(ty: &Type) -> syn::Result<String> {
    match last_segment(ty) {
        Some(segment) if segment.arguments.is_none() => Ok(client_ident(&segment.ident)),
        _ => Err(syn::Error::new_spanned(
            ty,
            "expected a named input type without generic arguments",
        )),
    }
}

fn client_ident(ident: &syn::Ident) -> String {
    format!("{ident}Client")
}

/// How the client value of a field becomes its circuit value. Types are
/// matched by the last segment of their path; every protocol type maps to its
/// `spr_program` path, so a type that only shares its name is refused where
/// the conversion assigns to it.
enum Kind<'a> {
    Context,
    Utxo,
    Address,
    Asset,
    Field,
    /// `UtxoOwner` or `SigningPubkey`: the client value is the circuit value.
    Owner(&'a syn::Ident),
    /// `ArrayVec<Utxo, N>`: every input is recorded.
    Utxos {
        capacity: &'a GenericArgument,
    },
    /// `ArrayVec<T, N>` of a plain `T`: only the capacity is checked.
    Bounded {
        item: &'a Type,
        capacity: &'a GenericArgument,
    },
    /// The client value is the circuit value.
    Plain,
    /// Another `ClientInputs` type, converted by its own derive.
    Nested(&'a syn::Ident),
}

/// Types the client passes as they are. Anything holding a protocol type or
/// another input type needs a conversion, so only these names may appear in
/// arrays, tuples and plain `ArrayVec`s.
const PLAIN: [&str; 14] = [
    "bool", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
    "String",
];

/// Whether `ty` is a plain name, or an array or tuple of plain types.
fn plain(ty: &Type) -> bool {
    match ungroup(ty) {
        Type::Array(array) => plain(&array.elem),
        Type::Tuple(tuple) => tuple.elems.iter().all(plain),
        _ => last_segment(ty).is_some_and(|segment| {
            segment.arguments.is_none() && PLAIN.iter().any(|name| segment.ident == name)
        }),
    }
}

fn classify(ty: &Type) -> syn::Result<Kind<'_>> {
    if plain(ty) {
        return Ok(Kind::Plain);
    }
    if matches!(ungroup(ty), Type::Array(_) | Type::Tuple(_)) {
        return Err(unsupported_collection(ty));
    }
    let Some(segment) = last_segment(ty) else {
        return Err(unsupported(ty));
    };
    let arguments = match &segment.arguments {
        PathArguments::AngleBracketed(arguments) if segment.ident == "ArrayVec" => arguments,
        PathArguments::None => {
            return Ok(match segment.ident.to_string().as_str() {
                "TxContext" => Kind::Context,
                "Utxo" => Kind::Utxo,
                "ShieldedAddress" => Kind::Address,
                "Asset" => Kind::Asset,
                "Field" => Kind::Field,
                "UtxoOwner" | "SigningPubkey" => Kind::Owner(&segment.ident),
                "ArrayVec" => return Err(expected_array_vec(ty)),
                _ => Kind::Nested(&segment.ident),
            })
        }
        _ => return Err(unsupported(ty)),
    };
    let mut arguments = arguments.args.iter();
    let (Some(GenericArgument::Type(item)), Some(capacity), None) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Err(expected_array_vec(ty));
    };
    match classify(item) {
        Ok(Kind::Utxo) => Ok(Kind::Utxos { capacity }),
        _ if plain(item) => Ok(Kind::Bounded { item, capacity }),
        _ => Err(unsupported_collection(ty)),
    }
}

fn unsupported(ty: &Type) -> syn::Error {
    syn::Error::new_spanned(
        ty,
        "unsupported client input type; use a plain value (an integer, bool or String, or an \
         array or tuple of them), TxContext, Utxo, ShieldedAddress, Asset, Field, UtxoOwner, \
         SigningPubkey, ArrayVec, or another input struct without generic arguments",
    )
}

fn unsupported_collection(ty: &Type) -> syn::Error {
    syn::Error::new_spanned(
        ty,
        "client inputs do not convert collections of this type; arrays, tuples and ArrayVec hold \
         plain values, and ArrayVec<Utxo, N> is the one collection that converts",
    )
}

fn expected_array_vec(ty: &Type) -> syn::Error {
    syn::Error::new_spanned(ty, "expected ArrayVec<Item, CAPACITY>")
}

/// How one field of a generated client view converts to its circuit value.
struct Mapping {
    client: TokenStream,
    converted: TokenStream,
    /// The TypeScript type, when Tsify cannot name the client type itself.
    ts: Option<String>,
    /// The wasm decoder, when the client type has no plain Serde decoding.
    deserialize_with: Option<&'static str>,
    /// The client value is the circuit value, so the view converts back.
    identity: bool,
}

impl Mapping {
    fn converted(client: TokenStream, converted: TokenStream, ts: Option<String>) -> Self {
        Self {
            client,
            converted,
            ts,
            deserialize_with: None,
            identity: false,
        }
    }

    fn identity(client: TokenStream, value: TokenStream) -> Self {
        Self {
            client,
            converted: value,
            ts: None,
            deserialize_with: None,
            identity: true,
        }
    }
}

/// Conversions are located at the field type, so a type that only shares a
/// protocol type's name fails at the field rather than at the derive. Names
/// still resolve at the derive: a type substituted by `macro_rules!` carries
/// that macro's hygiene, which cannot see `client` and `records`.
fn mapping(kind: Kind, ty: &Type, name: &syn::Ident) -> Mapping {
    let span = Span::call_site().located_at(ty.span());
    let value = quote_spanned!(span=> client.#name);
    match kind {
        Kind::Context => Mapping::converted(
            quote!(::spr_program::TransactionOptions),
            quote_spanned!(span=> #value.into_context()?),
            Some("TransactionOptions".into()),
        ),
        Kind::Utxo => Mapping::converted(
            quote!(::spr_program::__private::WalletUtxo),
            quote_spanned!(span=> records.utxo(&#value)?),
            Some("WalletUtxo".into()),
        ),
        Kind::Address => Mapping::converted(
            quote!(::spr_program::__private::NativeShieldedAddress),
            quote_spanned!(span=> records.address(&#value)?),
            Some("Uint8Array".into()),
        ),
        Kind::Asset => Mapping::converted(
            quote!(::spr_program::__private::Mint),
            quote_spanned!(span=> records.asset(#value)?),
            Some("Mint".into()),
        ),
        Kind::Field => Mapping {
            ts: Some("string".into()),
            deserialize_with: Some("::spr_program::wasm::deserialize_field"),
            ..Mapping::identity(quote!(::spr_program::Field), value)
        },
        Kind::Owner(ident) => Mapping::identity(quote!(::spr_program::#ident), value),
        Kind::Utxos { capacity } => Mapping::converted(
            quote!(::spr_program::__private::Vec<::spr_program::__private::WalletUtxo>),
            quote_spanned!(span=> records.utxos::<#capacity>(&#value)?),
            Some("WalletUtxo[]".into()),
        ),
        Kind::Bounded { item, capacity } => Mapping::converted(
            quote!(::spr_program::__private::Vec<#item>),
            quote_spanned!(span=> ::spr_program::InputRecords::bounded::<_, #capacity>(#value)?),
            None,
        ),
        Kind::Plain => Mapping::identity(quote!(#ty), value),
        Kind::Nested(ident) => Mapping {
            deserialize_with: Some("::spr_program::wasm::deserialize_client_input"),
            ..Mapping::converted(
                quote!(<#ty as ::spr_program::ClientInputs>::Client),
                quote_spanned!(span=> <#ty as ::spr_program::ClientInputs>::from_client(#value, records)?),
                Some(client_ident(ident)),
            )
        },
    }
}

#[cfg(test)]
#[path = "client_inputs_tests.rs"]
mod tests;
