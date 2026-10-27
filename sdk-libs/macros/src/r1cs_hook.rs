use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

use spr_zk_macros_core::{r1cs_hook, shape::Shape};

/// The r1cs export hook of a ZK program: its verifier hashes the public fields
/// with the private transaction hash.
pub(crate) fn generate(input: &DeriveInput, shape: &Shape) -> TokenStream {
    r1cs_hook::generate(
        input,
        shape,
        &quote!(::spr_program::__zk_program_r1cs),
        &quote!(::spr_program::__private::write_program_r1cs),
    )
}
