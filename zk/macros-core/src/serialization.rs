use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, Type};

use crate::{paths, shape::Shape};

pub(crate) fn generate(input: &DeriveInput, shape: &Shape) -> TokenStream {
    if !input.generics.params.is_empty() {
        return TokenStream::new();
    }
    let ident = &input.ident;
    let private = paths::private();
    let serde_module = format_ident!("__zk_serde_{}", ident);
    let tsify_module = format_ident!("__zk_tsify_{}", ident);
    let remote = format!("super::{ident}");

    let fields = shape.fields();
    let serde_fields = fields.iter().map(|field| {
        let (field_ident, field_ty) = (field.ident, field.ty);
        let with = match Representation::of(field_ty) {
            Representation::Bytes => quote!(#[serde(with = "::zolana_program::__private::bytes")]),
            Representation::Array => quote!(#[serde(with = "::zolana_program::__private::array")]),
            Representation::Address => {
                quote!(#[serde(with = "::zolana_program::__private::address")])
            }
            Representation::Serde => TokenStream::new(),
        };
        quote!(#with pub(super) #field_ident: #field_ty)
    });
    let tsify_fields = fields.iter().map(|field| {
        let (field_ident, field_ty) = (field.ident, field.ty);
        let ty = match Representation::of(field_ty) {
            Representation::Bytes => quote!(#[tsify(type = "Uint8Array")]),
            Representation::Address => quote!(#[tsify(type = "string")]),
            Representation::Array | Representation::Serde => TokenStream::new(),
        };
        quote!(#ty pub(super) #field_ident: #field_ty)
    });
    let (serde_body, tsify_body) = match shape {
        Shape::Named(_) => (
            quote!({ #(#serde_fields,)* }),
            quote!({ #(#tsify_fields,)* }),
        ),
        Shape::Unit => (quote!(;), quote!(;)),
    };

    quote! {
        ::zolana_program::__proof_input_serde! {
            #[doc(hidden)]
            #[allow(non_snake_case, unused_imports, clippy::all)]
            mod #serde_module {
                use super::*;

                #[derive(#private::serde::Serialize, #private::serde::Deserialize)]
                #[serde(
                    crate = "::zolana_program::__private::serde",
                    remote = #remote,
                    rename_all = "camelCase",
                    deny_unknown_fields
                )]
                pub(super) struct #ident #serde_body
            }

            impl #private::serde::Serialize for #ident {
                fn serialize<__S: #private::serde::Serializer>(
                    &self,
                    serializer: __S,
                ) -> ::core::result::Result<__S::Ok, __S::Error> {
                    #serde_module::#ident::serialize(self, serializer)
                }
            }

            impl<'de> #private::serde::Deserialize<'de> for #ident {
                fn deserialize<__D: #private::serde::Deserializer<'de>>(
                    deserializer: __D,
                ) -> ::core::result::Result<Self, __D::Error> {
                    #serde_module::#ident::deserialize(deserializer)
                }
            }
        }

        ::zolana_program::__proof_input_tsify! {
            #[doc(hidden)]
            #[allow(non_snake_case, unused_imports, clippy::all)]
            mod #tsify_module {
                use super::*;
                use #private::{tsify, wasm_bindgen};

                #[derive(#private::tsify::Tsify)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                #[tsify(large_number_types_as_bigints)]
                pub struct #ident #tsify_body
            }

            impl #private::tsify::Tsify for #ident {
                type JsType = <#tsify_module::#ident as #private::tsify::Tsify>::JsType;
                const DECL: &'static str = <#tsify_module::#ident as #private::tsify::Tsify>::DECL;
                const SERIALIZATION_CONFIG: #private::tsify::SerializationConfig =
                    <#tsify_module::#ident as #private::tsify::Tsify>::SERIALIZATION_CONFIG;
            }
        }
    }
}

enum Representation {
    Bytes,
    Array,
    Address,
    Serde,
}

impl Representation {
    fn of(ty: &Type) -> Self {
        match ty {
            Type::Array(array) if is_path(&array.elem, "u8") => Self::Bytes,
            Type::Array(_) => Self::Array,
            Type::Path(path)
                if path.qself.is_none()
                    && path.path.segments.last().is_some_and(|segment| {
                        segment.ident == "Address" && segment.arguments.is_none()
                    }) =>
            {
                Self::Address
            }
            _ => Self::Serde,
        }
    }
}

fn is_path(ty: &Type, ident: &str) -> bool {
    matches!(ty, Type::Path(path) if path.qself.is_none() && path.path.is_ident(ident))
}
