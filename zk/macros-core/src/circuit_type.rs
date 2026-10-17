use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::{
    paths, proof_input,
    shape::{twin_ident, Shape},
};

/// The generated pieces of a circuit type, kept apart so a derive that adds
/// impls can place them in its own order.
pub struct CircuitTypeParts {
    pub proof_input: TokenStream,
    pub defaults: TokenStream,
    pub from_circuit: TokenStream,
}

pub fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    shape.check_no_bounds("circuit types")?;
    let CircuitTypeParts {
        proof_input,
        defaults,
        from_circuit,
    } = generate(input, &shape);
    Ok(quote! {
        #proof_input

        #defaults

        #from_circuit
    })
}

pub fn generate(input: &DeriveInput, shape: &Shape) -> CircuitTypeParts {
    let proof_input = proof_input::generate(input, shape);
    let ident = &input.ident;
    let twin = twin_ident(ident);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let circuit_error = paths::circuit_error();
    let circuit_default = paths::circuit_default();
    let from_circuit = paths::from_circuit();

    let (default_value, from_circuit_body) = match shape {
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
                    ) -> ::core::result::Result<Self, #circuit_error> {
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
                ) -> ::core::result::Result<Self, #circuit_error> {
                    ::core::result::Result::Ok(Self)
                }
            },
        ),
    };

    CircuitTypeParts {
        proof_input,
        defaults: quote! {
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
        },
        from_circuit: quote! {
            impl #impl_generics #from_circuit for #ident #ty_generics #where_clause {
                #from_circuit_body
            }
        },
    }
}
