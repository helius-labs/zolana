use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::{
    paths,
    shape::{twin_ident, Shape},
};

pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    Ok(generate(input, &shape))
}

pub(crate) fn generate(input: &DeriveInput, shape: &Shape) -> TokenStream {
    let ident = &input.ident;
    let vis = &input.vis;
    let twin = twin_ident(ident);
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let proof_input = paths::proof_input();
    let placeholder = paths::placeholder();
    let allocator = paths::allocator();
    let relation_error = paths::relation_error();
    let circuit_type = paths::circuit_type();

    let (twin_struct, instantiate, placeholder_value) = match shape {
        Shape::Named(fields) => {
            let definitions = fields.iter().map(|field| {
                let (field_vis, field_ident, field_ty) = (field.vis, field.ident, field.ty);
                quote!(#field_vis #field_ident: <#field_ty as #proof_input>::Circuit)
            });
            let instantiated = fields.iter().map(|field| {
                let (field_ident, field_ty) = (field.ident, field.ty);
                quote!(#field_ident: <#field_ty as #proof_input>::instantiate(&self.#field_ident, allocator)?)
            });
            let placeholders = fields.iter().map(|field| {
                let (field_ident, field_ty) = (field.ident, field.ty);
                quote!(#field_ident: <#field_ty as #placeholder>::placeholder()?)
            });
            (
                quote! {
                    #[derive(Clone, Debug)]
                    #vis struct #twin #generics #where_clause {
                        #(#definitions,)*
                    }
                },
                quote! {
                    fn instantiate(
                        &self,
                        allocator: &#allocator,
                    ) -> ::core::result::Result<Self::Circuit, #relation_error> {
                        ::core::result::Result::Ok(#twin {
                            #(#instantiated,)*
                        })
                    }
                },
                quote!(Self { #(#placeholders,)* }),
            )
        }
        Shape::Unit => (
            quote! {
                #[derive(Clone, Debug)]
                #vis struct #twin #generics #where_clause;
            },
            quote! {
                fn instantiate(
                    &self,
                    _allocator: &#allocator,
                ) -> ::core::result::Result<Self::Circuit, #relation_error> {
                    ::core::result::Result::Ok(#twin)
                }
            },
            quote!(Self),
        ),
    };

    quote! {
        #twin_struct

        impl #impl_generics #proof_input for #ident #ty_generics #where_clause {
            type Circuit = #twin #ty_generics;

            #instantiate
        }

        impl #impl_generics #placeholder for #ident #ty_generics #where_clause {
            fn placeholder() -> ::core::result::Result<Self, #relation_error> {
                ::core::result::Result::Ok(#placeholder_value)
            }
        }

        impl #impl_generics #circuit_type for #twin #ty_generics #where_clause {}
    }
}
