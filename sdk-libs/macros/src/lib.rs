use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod circuit_type;
#[cfg(test)]
mod discriminator_tests;
mod error_name;
mod paths;
mod proof_input;
mod public_inputs;
mod r1cs_hook;
mod serialization;
mod shape;
mod zk_program_wasm;

#[doc(hidden)]
#[proc_macro_derive(ErrorName, attributes(error_name))]
pub fn derive_error_name(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(error_name::expand(&input))
}

#[proc_macro_derive(ProofInput, attributes(max_len, min_len))]
pub fn derive_proof_input(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(proof_input::expand(&input))
}

#[proc_macro_derive(PublicInputs, attributes(max_len, min_len))]
pub fn derive_public_inputs(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(public_inputs::expand(&input))
}

#[proc_macro_derive(CircuitType, attributes(max_len, min_len))]
pub fn derive_circuit_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(circuit_type::expand(&input))
}

fn into_token_stream(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    result
        .unwrap_or_else(|error| error.to_compile_error())
        .into()
}
