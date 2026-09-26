use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::{
    discriminator::state_discriminator,
    paths, proof_input,
    shape::{twin_ident, Shape},
};

pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    shape.check_hashed_field_count(input, "states")?;
    let proof_input = proof_input::generate(input, &shape);
    let ident = &input.ident;
    let twin = twin_ident(ident);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let discriminator = state_discriminator(&ident.to_string());
    let hasher = paths::hasher();
    let data_hash = paths::data_hash();
    let circuit_var = paths::circuit_var();
    let relation_error = paths::relation_error();
    let poseidon = paths::poseidon();
    let constant = paths::constant();
    let circuit_default = paths::circuit_default();
    let from_circuit = paths::from_circuit();
    let utxo_data = paths::utxo_data();
    let checked_utxo_data = paths::checked_utxo_data();

    let fields = shape.fields();
    let circuit_hashes = fields.iter().map(|field| {
        let field_ident = field.ident;
        quote!(#data_hash::hash(&self.#field_ident)?)
    });
    let byte_hashes = fields.iter().map(|field| {
        let field_ident = field.ident;
        quote!(#hasher::ToByteArray::to_byte_array(&self.#field_ident)?.as_slice())
    });
    let (default_value, from_circuit_body) = match &shape {
        Shape::Named(fields) => {
            let defaults = fields.iter().map(|field| {
                let field_ident = field.ident;
                quote!(#field_ident: #circuit_default::circuit_default())
            });
            let converted = fields.iter().map(|field| {
                let (field_ident, field_ty) = (field.ident, field.ty);
                quote!(#field_ident: <#field_ty as #from_circuit>::from_circuit(&circuit.#field_ident)?)
            });
            (
                quote!(Self { #(#defaults,)* }),
                quote! {
                    fn from_circuit(
                        circuit: &Self::Circuit,
                    ) -> ::core::result::Result<Self, #relation_error> {
                        ::core::result::Result::Ok(Self { #(#converted,)* })
                    }
                },
            )
        }
        Shape::Unit => (
            quote!(Self),
            quote! {
                fn from_circuit(
                    _circuit: &Self::Circuit,
                ) -> ::core::result::Result<Self, #relation_error> {
                    ::core::result::Result::Ok(Self)
                }
            },
        ),
    };

    Ok(quote! {
        #proof_input

        impl #impl_generics #hasher::Discriminator for #ident #ty_generics #where_clause {
            const DISCRIMINATOR: [u8; 8] = [#(#discriminator),*];
        }

        impl #impl_generics #data_hash for #twin #ty_generics #where_clause {
            fn hash(&self) -> ::core::result::Result<#circuit_var, #relation_error> {
                #poseidon(&[
                    #constant(u64::from_be_bytes(
                        <#ident #ty_generics as #hasher::Discriminator>::DISCRIMINATOR,
                    )),
                    #(#circuit_hashes,)*
                ])
            }
        }

        impl #impl_generics #hasher::DataHasher for #ident #ty_generics #where_clause {
            fn hash<H: #hasher::Hasher>(
                &self,
            ) -> ::core::result::Result<[u8; 32], #hasher::HasherError> {
                H::hashv(&[
                    #hasher::ToByteArray::to_byte_array(&u64::from_be_bytes(
                        <Self as #hasher::Discriminator>::DISCRIMINATOR,
                    ))?
                    .as_slice(),
                    #(#byte_hashes,)*
                ])
            }
        }

        impl #impl_generics #hasher::ToByteArray for #ident #ty_generics #where_clause {
            fn to_byte_array(&self) -> ::core::result::Result<[u8; 32], #hasher::HasherError> {
                <Self as #hasher::DataHasher>::hash::<#hasher::Poseidon>(self)
            }
        }

        impl #impl_generics #circuit_default for #twin #ty_generics #where_clause {
            fn circuit_default() -> Self {
                #default_value
            }
        }

        impl #impl_generics ::core::default::Default for #twin #ty_generics #where_clause {
            fn default() -> Self {
                <Self as #circuit_default>::circuit_default()
            }
        }

        impl #impl_generics #from_circuit for #ident #ty_generics #where_clause {
            #from_circuit_body
        }

        impl #impl_generics #utxo_data for #twin #ty_generics #where_clause {
            type Client = #ident #ty_generics;

            fn utxo_data(&self) -> ::core::result::Result<::std::vec::Vec<u8>, #relation_error> {
                #checked_utxo_data(self)
            }
        }
    })
}
