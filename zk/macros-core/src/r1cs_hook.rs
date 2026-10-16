use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

use crate::{
    paths,
    shape::{snake_case, Shape},
};

/// The r1cs export hook of a `private` + `public` circuit: a `#[test]` named
/// `__zk_r1cs_<snake_case name>` (the `zolana_zk_dsl::r1cs_hook` contract),
/// emitted only when `gate` (a feature-gated `macro_rules!`) is enabled.
/// `writer` takes the circuit name and the public type's layout.
pub fn generate(
    input: &DeriveInput,
    shape: &Shape,
    gate: &TokenStream,
    writer: &TokenStream,
) -> TokenStream {
    if !input.generics.params.is_empty() || !shape.is_program() {
        return TokenStream::new();
    }
    let Some(public) = shape.fields().iter().find(|field| field.ident == "public") else {
        return TokenStream::new();
    };
    let ident = &input.ident;
    let public = public.ty;
    let public_input_layout = paths::public_input_layout();
    let name = snake_case(&ident.to_string());
    let test = format_ident!("__zk_r1cs_{}", name);
    quote! {
        #gate! {
            #[test]
            #[doc(hidden)]
            fn #test() {
                #writer::<#ident>(
                    #name,
                    &<#public as #public_input_layout>::layout(),
                );
            }
        }
    }
}
