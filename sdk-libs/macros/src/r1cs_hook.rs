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
    let Some(public) = shape.fields().iter().find(|field| field.ident == "public") else {
        return TokenStream::new();
    };
    let ident = &input.ident;
    let public = public.ty;
    let public_input_layout = paths::public_input_layout();
    let name = snake_case(&ident.to_string());
    let test = format_ident!("__zk_r1cs_{}", name);
    quote! {
        ::zolana_program::__zk_program_r1cs! {
            #[test]
            #[doc(hidden)]
            fn #test() {
                ::zolana_program::__private::write_r1cs::<#ident>(
                    #name,
                    &<#public as #public_input_layout>::layout(),
                );
            }
        }
    }
}
