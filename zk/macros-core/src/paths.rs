use proc_macro2::TokenStream;
use quote::quote;

pub fn proof_input() -> TokenStream {
    quote!(::zolana_program::conversion::ProofInput)
}

pub fn placeholder() -> TokenStream {
    quote!(::zolana_program::conversion::Placeholder)
}

pub fn instantiate_padded() -> TokenStream {
    quote!(::zolana_program::conversion::instantiate_padded)
}

pub fn placeholders() -> TokenStream {
    quote!(::zolana_program::conversion::placeholders)
}

pub fn from_circuit() -> TokenStream {
    quote!(::zolana_program::conversion::FromCircuit)
}

pub fn allocator() -> TokenStream {
    quote!(::zolana_program::conversion::Allocator)
}

pub fn circuit_error() -> TokenStream {
    quote!(::zolana_program::CircuitError)
}

pub fn circuit_type() -> TokenStream {
    quote!(::zolana_program::circuit::CircuitType)
}

pub fn circuit_default() -> TokenStream {
    quote!(::zolana_program::circuit::CircuitDefault)
}

pub fn circuit_var() -> TokenStream {
    quote!(::zolana_program::circuit::CircuitVar)
}

pub fn constant() -> TokenStream {
    quote!(::zolana_program::circuit::constant)
}

pub fn private() -> TokenStream {
    quote!(::zolana_program::__private)
}

pub fn public_field() -> TokenStream {
    quote!(::zolana_program::PublicField)
}

pub fn public_field_kind() -> TokenStream {
    quote!(::zolana_program::PublicFieldKind)
}

pub fn public_input_layout() -> TokenStream {
    quote!(::zolana_program::PublicInputLayout)
}

pub fn public_value() -> TokenStream {
    quote!(::zolana_program::circuit::PublicValue)
}
