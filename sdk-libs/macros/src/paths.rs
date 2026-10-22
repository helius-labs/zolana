use proc_macro2::TokenStream;
use quote::quote;
pub(crate) use zolana_zk_macros_core::paths::*;

pub(crate) fn data_hash() -> TokenStream {
    quote!(::zolana_program::circuit::DataHash)
}

pub(crate) fn utxo_data() -> TokenStream {
    quote!(::zolana_program::circuit::UtxoData)
}

pub(crate) fn public_inputs() -> TokenStream {
    quote!(::zolana_program::circuit::PublicInputs)
}

pub(crate) fn public_hash_field() -> TokenStream {
    quote!(::zolana_program::PublicHashField)
}

pub(crate) fn poseidon() -> TokenStream {
    quote!(::zolana_program::circuit::poseidon)
}

pub(crate) fn hasher() -> TokenStream {
    quote!(::zolana_program::hasher)
}

pub(crate) fn wasm() -> TokenStream {
    quote!(::zolana_program::wasm)
}
