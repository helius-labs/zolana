use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::{
    paths,
    shape::{twin_ident, Shape},
};

pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    shape.check_hashed_field_count(input, "public inputs")?;
    let twin = twin_ident(&input.ident);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let public_inputs = paths::public_inputs();
    let data_hash = paths::data_hash();
    let circuit_var = paths::circuit_var();
    let relation_error = paths::relation_error();
    let poseidon = paths::poseidon();

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
        impl #impl_generics #public_inputs for #twin #ty_generics #where_clause {
            fn hash(
                &self,
                transaction_hash: &#circuit_var,
            ) -> ::core::result::Result<#circuit_var, #relation_error> {
                #hash
            }
        }
    })
}
