use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::{spanned::Spanned, DeriveInput, Result};

use zolana_zk_macros_core::{
    proof_input,
    shape::{twin_ident, Shape},
};

use crate::paths;

pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    shape.check_hashed_field_count(input, "public inputs")?;
    shape.check_no_bounds("public inputs")?;
    let proof_input = proof_input::generate(input, &shape);
    let twin = twin_ident(&input.ident);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let public_inputs = paths::public_inputs();
    let data_hash = paths::data_hash();
    let circuit_var = paths::circuit_var();
    let circuit_error = paths::circuit_error();
    let poseidon = paths::poseidon();

    let layout = layout(input, &shape);

    let hash = match shape {
        Shape::Named(fields) => {
            let field_hashes = fields.iter().map(|field| {
                let field_ident = field.ident;
                quote!(#data_hash::hash(&self.#field_ident)?)
            });
            quote! {
                #poseidon(&[
                    #(#field_hashes,)*
                    ::core::clone::Clone::clone(transaction_hash),
                ])
            }
        }
        Shape::Unit => quote!(#poseidon(::core::slice::from_ref(transaction_hash))),
    };

    Ok(quote! {
        #proof_input

        #layout

        impl #impl_generics #public_inputs for #twin #ty_generics #where_clause {
            fn hash(
                &self,
                transaction_hash: &#circuit_var,
            ) -> ::core::result::Result<#circuit_var, #circuit_error> {
                #hash
            }
        }
    })
}

fn layout(input: &DeriveInput, shape: &Shape) -> TokenStream {
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let public_input_layout = paths::public_input_layout();
    let public_field = paths::public_field();
    let public_field_kind = paths::public_field_kind();
    let entries = shape.fields().iter().map(|field| {
        let name = field.ident.to_string();
        let ty = field.ty;
        quote_spanned!(ty.span()=> (#name, <#ty as #public_field>::kind()))
    });
    quote! {
        impl #impl_generics #public_input_layout for #ident #ty_generics #where_clause {
            fn layout() -> ::std::vec::Vec<(&'static str, #public_field_kind)> {
                ::std::vec![#(#entries),*]
            }
        }
    }
}
