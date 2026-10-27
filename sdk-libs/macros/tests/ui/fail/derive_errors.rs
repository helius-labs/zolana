use spr_program::{
    circuit::{UtxoState, PublicInputs},
    conversion::ProofInput,
};

#[derive(ProofInput)]
struct Amount(u64);

#[derive(ProofInput)]
enum Choice {
    A,
}

#[derive(PublicInputs)]
struct TooManyPublicInputs {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
    i: u64,
    j: u64,
    k: u64,
    l: u64,
}

#[derive(UtxoState)]
struct TooManyStateFields {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
    g: u64,
    h: u64,
    i: u64,
    j: u64,
    k: u64,
    l: u64,
}

fn main() {}
