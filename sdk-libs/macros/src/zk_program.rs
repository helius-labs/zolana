use quote::quote;
use syn::{DeriveInput, Result};
use zolana_zk_macros_core::{proof_input, shape::Shape};

use crate::{r1cs_hook, zk_program_wasm};

pub(crate) fn expand(input: &DeriveInput) -> Result<proc_macro2::TokenStream> {
    let shape = Shape::of(input)?;
    if !shape.is_program() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "a ZK program is a struct with exactly the fields `private` and `public`",
        ));
    }
    let wasm = zk_program_wasm::generate(input, &shape);
    let r1cs = r1cs_hook::generate(input, &shape);
    Ok(proof_input::generate_with(
        input,
        &shape,
        quote! {
            #wasm

            #r1cs
        },
    ))
}
