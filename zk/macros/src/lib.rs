use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};
use zolana_zk_macros_core::{circuit_type, error_name, proof_input, public_inputs, zk_circuit};

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

/// Regular public inputs: every field is bound directly as the proof's public
/// inputs, in declaration order. Use the struct's circuit twin in a
/// `Public<_>` circuit output.
#[proc_macro_derive(PublicInputs, attributes(max_len, min_len))]
pub fn derive_public_inputs(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(public_inputs::expand(&input))
}

/// A circuit with regular public inputs: a struct with exactly the fields
/// `private` and `public`, whose circuit returns `Public<_>` of its public
/// inputs. Emits its proof input and, with the `r1cs-export` feature, the hook
/// `zolana zk compile` runs to export its r1cs and verifier module.
#[proc_macro_derive(ZkCircuit, attributes(max_len, min_len))]
pub fn derive_zk_circuit(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    into_token_stream(zk_circuit::expand(&input))
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
