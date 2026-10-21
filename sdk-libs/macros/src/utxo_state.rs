use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use zolana_zk_macros_core::{
    circuit_type::{self, CircuitTypeParts},
    shape::{twin_ident, Shape},
};

use crate::{encryption_codec, paths, zk_program_wasm};

pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    shape.check_hashed_field_count(input, "states")?;
    shape.check_no_bounds("states")?;
    let encryption_codec = encryption_codec::generate(input)?;
    let CircuitTypeParts {
        proof_input,
        defaults,
        from_circuit,
    } = circuit_type::generate(input, &shape);
    let data_utxo_wasm = zk_program_wasm::data_utxo(input);
    let ident = &input.ident;
    let twin = twin_ident(ident);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let mut utxo_generics = input.generics.clone();
    utxo_generics
        .make_where_clause()
        .predicates
        .push(syn::parse_quote!(
            #ident #ty_generics: ::zolana_program::EncryptionCodec
        ));
    let (utxo_impl_generics, _, utxo_where_clause) = utxo_generics.split_for_impl();
    let discriminator = zolana_hasher::state_discriminator(&ident.to_string())
        .map_err(|error| syn::Error::new_spanned(ident, error.to_string()))?;
    let hasher = paths::hasher();
    let data_hash = paths::data_hash();
    let circuit_var = paths::circuit_var();
    let circuit_error = paths::circuit_error();
    let poseidon = paths::poseidon();
    let constant = paths::constant();
    let utxo_data = paths::utxo_data();

    let fields = shape.fields();
    let circuit_hashes = fields.iter().map(|field| {
        let field_ident = field.ident;
        quote!(#data_hash::hash(&self.#field_ident)?)
    });
    let byte_hashes = fields.iter().map(|field| {
        let field_ident = field.ident;
        quote!(#hasher::ToByteArray::to_byte_array(&self.#field_ident)?.as_slice())
    });
    Ok(quote! {
        #proof_input

        #data_utxo_wasm

        #encryption_codec

        impl #impl_generics #hasher::Discriminator for #ident #ty_generics #where_clause {
            const DISCRIMINATOR: [u8; 8] = [#(#discriminator),*];
        }

        impl #impl_generics #data_hash for #twin #ty_generics #where_clause {
            fn hash(&self) -> ::core::result::Result<#circuit_var, #circuit_error> {
                #poseidon(&[
                    #constant(u64::from_be_bytes(
                        <#ident #ty_generics as #hasher::Discriminator>::DISCRIMINATOR,
                    )),
                    #(#circuit_hashes,)*
                ])
            }
        }

        impl #impl_generics #hasher::DataHasher for #ident #ty_generics #where_clause {
            fn hash(
                &self,
            ) -> ::core::result::Result<[u8; 32], #hasher::HasherError> {
                <#hasher::Poseidon as #hasher::Hasher>::hashv(&[
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
                <Self as #hasher::DataHasher>::hash(self)
            }
        }

        #defaults

        #from_circuit

        impl #utxo_impl_generics #utxo_data for #twin #ty_generics #utxo_where_clause {
            type Client = #ident #ty_generics;

        }
    })
}
