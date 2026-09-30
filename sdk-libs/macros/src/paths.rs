use proc_macro2::TokenStream;
use quote::quote;

pub(crate) fn proof_input() -> TokenStream {
    quote!(::zolana_program::conversion::ProofInput)
}

pub(crate) fn placeholder() -> TokenStream {
    quote!(::zolana_program::conversion::Placeholder)
}

pub(crate) fn instantiate_padded() -> TokenStream {
    quote!(::zolana_program::conversion::instantiate_padded)
}

pub(crate) fn placeholders() -> TokenStream {
    quote!(::zolana_program::conversion::placeholders)
}

pub(crate) fn from_circuit() -> TokenStream {
    quote!(::zolana_program::conversion::FromCircuit)
}

pub(crate) fn allocator() -> TokenStream {
    quote!(::zolana_program::conversion::Allocator)
}

pub(crate) fn circuit_error() -> TokenStream {
    quote!(::zolana_program::CircuitError)
}

pub(crate) fn circuit_type() -> TokenStream {
    quote!(::zolana_program::circuit::CircuitType)
}

pub(crate) fn circuit_default() -> TokenStream {
    quote!(::zolana_program::circuit::CircuitDefault)
}

pub(crate) fn circuit_var() -> TokenStream {
    quote!(::zolana_program::circuit::CircuitVar)
}

pub(crate) fn data_hash() -> TokenStream {
    quote!(::zolana_program::circuit::DataHash)
}

pub(crate) fn utxo_data() -> TokenStream {
    quote!(::zolana_program::circuit::UtxoData)
}

pub(crate) fn public_inputs() -> TokenStream {
    quote!(::zolana_program::circuit::PublicInputs)
}

pub(crate) fn checked_utxo_data() -> TokenStream {
    quote!(::zolana_program::circuit::checked_utxo_data)
}

pub(crate) fn poseidon() -> TokenStream {
    quote!(::zolana_program::circuit::poseidon)
}

pub(crate) fn constant() -> TokenStream {
    quote!(::zolana_program::circuit::constant)
}

pub(crate) fn hasher() -> TokenStream {
    quote!(::zolana_program::hasher)
}

pub(crate) fn wasm() -> TokenStream {
    quote!(::zolana_program::wasm)
}

pub(crate) fn private() -> TokenStream {
    quote!(::zolana_program::__private)
}
