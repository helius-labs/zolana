use proc_macro2::TokenStream;
use quote::quote;

pub(crate) fn proof_input() -> TokenStream {
    quote!(::zk_program_sdk::conversion::ProofInput)
}

pub(crate) fn placeholder() -> TokenStream {
    quote!(::zk_program_sdk::conversion::Placeholder)
}

pub(crate) fn from_circuit() -> TokenStream {
    quote!(::zk_program_sdk::conversion::FromCircuit)
}

pub(crate) fn allocator() -> TokenStream {
    quote!(::zk_program_sdk::conversion::Allocator)
}

pub(crate) fn relation_error() -> TokenStream {
    quote!(::zk_program_sdk::RelationError)
}

pub(crate) fn circuit_type() -> TokenStream {
    quote!(::zk_program_sdk::circuit::CircuitType)
}

pub(crate) fn circuit_default() -> TokenStream {
    quote!(::zk_program_sdk::circuit::CircuitDefault)
}

pub(crate) fn circuit_marker() -> TokenStream {
    quote!(::zk_program_sdk::circuit::CircuitMarker)
}

pub(crate) fn circuit_var() -> TokenStream {
    quote!(::zk_program_sdk::circuit::CircuitVar)
}

pub(crate) fn data_hash() -> TokenStream {
    quote!(::zk_program_sdk::circuit::DataHash)
}

pub(crate) fn utxo_data() -> TokenStream {
    quote!(::zk_program_sdk::circuit::UtxoData)
}

pub(crate) fn public_inputs() -> TokenStream {
    quote!(::zk_program_sdk::circuit::PublicInputs)
}

pub(crate) fn checked_utxo_data() -> TokenStream {
    quote!(::zk_program_sdk::circuit::checked_utxo_data)
}

pub(crate) fn poseidon() -> TokenStream {
    quote!(::zk_program_sdk::circuit::poseidon)
}

pub(crate) fn constant() -> TokenStream {
    quote!(::zk_program_sdk::circuit::constant)
}

pub(crate) fn hasher() -> TokenStream {
    quote!(::zk_program_sdk::hasher)
}

pub(crate) fn wasm() -> TokenStream {
    quote!(::zk_program_sdk::wasm)
}
