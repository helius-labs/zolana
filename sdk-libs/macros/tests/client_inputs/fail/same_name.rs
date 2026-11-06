// The client view gates on the wasm feature, which this crate does not declare.
#![allow(unexpected_cfgs)]

use spr_program::ClientInputs;

mod local {
    #[derive(Clone, Copy, Debug)]
    pub struct Utxo;
    #[derive(Clone, Copy, Debug)]
    pub struct UtxoOwner;
}

// Matched by name, but not the protocol types: each error points at its field.
#[derive(ClientInputs)]
pub struct Bad {
    pub deposit: local::Utxo,
    pub creator: local::UtxoOwner,
}

fn main() {}
