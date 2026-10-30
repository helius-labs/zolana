use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod program;
mod client_inputs;
mod encryption_codec;

fn tokens(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    result.unwrap_or_else(|error| error.to_compile_error()).into()
}

/// Derives the native client representation and checked protocol conversions.
#[proc_macro_derive(ClientInputs, attributes(client))]
pub fn client_inputs(input: TokenStream) -> TokenStream {
    tokens(client_inputs::expand(&parse_macro_input!(input as DeriveInput)))
}

#[proc_macro_derive(ZkProgram, attributes(zk_program))]
pub fn program(input: TokenStream) -> TokenStream {
    tokens(program::program(&parse_macro_input!(input as DeriveInput)))
}

#[proc_macro_derive(PublicInputs, attributes(client))]
pub fn public(input: TokenStream) -> TokenStream {
    tokens(program::public(&parse_macro_input!(input as DeriveInput)))
}

#[proc_macro_derive(UtxoState, attributes(utxo_state))]
pub fn state(input: TokenStream) -> TokenStream {
    tokens(program::state(&parse_macro_input!(input as DeriveInput)))
}
