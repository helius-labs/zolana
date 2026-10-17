use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

#[cfg(test)]
mod discriminator_tests;
mod paths;
mod public_inputs;
mod r1cs_hook;
mod utxo_state;
mod zk_program;
mod zk_program_wasm;

/// A ZK program's proof inputs: a struct with exactly the fields `private` and
/// `public`. Derives `ProofInput` plus the program's wasm bindings and r1cs
/// export hook.
#[proc_macro_derive(ZkProgram, attributes(max_len, min_len))]
pub fn derive_zk_program(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(zk_program::expand(&input))
}

#[proc_macro_derive(PublicInputs, attributes(max_len, min_len))]
pub fn derive_public_inputs(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(public_inputs::expand(&input))
}

/// State kept in a data utxo: its circuit type plus the discriminator and the
/// data hash that commit it.
#[proc_macro_derive(UtxoState, attributes(max_len, min_len))]
pub fn derive_utxo_state(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(utxo_state::expand(&input))
}

fn into_token_stream(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    result
        .unwrap_or_else(|error| error.to_compile_error())
        .into()
}
