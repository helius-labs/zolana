use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod circuit;
mod circuit_type;
mod discriminator;
mod paths;
mod proof_input;
mod public_inputs;
mod shape;

#[proc_macro_derive(ProofInput)]
pub fn derive_proof_input(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(proof_input::expand(&input))
}

#[proc_macro_derive(PublicInputs)]
pub fn derive_public_inputs(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(public_inputs::expand(&input))
}

#[proc_macro_derive(CircuitType)]
pub fn derive_circuit_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(circuit_type::expand(&input))
}

#[proc_macro_attribute]
pub fn circuit(attr: TokenStream, item: TokenStream) -> TokenStream {
    circuit::expand(attr.into(), item.into()).into()
}

fn into_token_stream(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    result
        .unwrap_or_else(|error| error.to_compile_error())
        .into()
}
