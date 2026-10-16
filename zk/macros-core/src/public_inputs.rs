use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::{spanned::Spanned, DeriveInput, Result};

use crate::{
    paths, proof_input,
    shape::{twin_ident, Shape},
};

/// `#[derive(PublicInputs)]` for regular public inputs: every field is bound
/// directly as the proof's public inputs, in declaration order.
pub fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let shape = Shape::of(input)?;
    shape.check_no_bounds("public inputs")?;
    let proof_input = proof_input::generate(input, &shape);
    let layout = layout(input, &shape, &paths::public_field());
    let public_value = public_value(input, &shape);
    Ok(quote! {
        #proof_input

        #layout

        #public_value
    })
}

/// The `PublicInputLayout` of a public inputs struct. `bound` is the trait
/// every field type must implement; its `#[diagnostic::on_unimplemented]`
/// names the offending field.
pub fn layout(input: &DeriveInput, shape: &Shape, bound: &TokenStream) -> TokenStream {
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let public_input_layout = paths::public_input_layout();
    let public_field_kind = paths::public_field_kind();
    let entries = shape.fields().iter().map(|field| {
        let name = field.ident.to_string();
        let ty = field.ty;
        quote_spanned!(ty.span()=> (#name, {
            fn kind<T: #bound>() -> #public_field_kind {
                T::kind()
            }
            kind::<#ty>()
        }))
    });
    quote! {
        impl #impl_generics #public_input_layout for #ident #ty_generics #where_clause {
            fn layout() -> ::std::vec::Vec<(&'static str, #public_field_kind)> {
                ::std::vec![#(#entries),*]
            }
        }
    }
}

fn public_value(input: &DeriveInput, shape: &Shape) -> TokenStream {
    let twin = twin_ident(&input.ident);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let public_value = paths::public_value();
    let proof_input = paths::proof_input();
    let circuit_var = paths::circuit_var();
    let counts = shape.fields().iter().map(|field| {
        let ty = field.ty;
        quote_spanned!(ty.span()=> <<#ty as #proof_input>::Circuit as #public_value>::PUBLIC_INPUTS)
    });
    let pushes = shape.fields().iter().map(|field| {
        let ident = field.ident;
        quote!(#public_value::public_inputs(&self.#ident, inputs);)
    });
    let inputs = if shape.fields().is_empty() {
        quote!(_inputs)
    } else {
        quote!(inputs)
    };
    quote! {
        impl #impl_generics #public_value for #twin #ty_generics #where_clause {
            const PUBLIC_INPUTS: usize = 0 #(+ #counts)*;

            fn public_inputs(&self, #inputs: &mut ::std::vec::Vec<#circuit_var>) {
                #(#pushes)*
            }
        }
    }
}
