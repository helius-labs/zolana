//! The native references the gadgets are checked against: `zolana_hasher`'s
//! Poseidon, and the nonzero hash chain written from
//! `zolana_transaction`'s `nonzero_hash_chain`, which the SDK's gadget
//! mirrors.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use proptest::prelude::*;
use zk_program_sdk::circuit::Field;
use zolana_hasher::{Hasher, HasherError, Poseidon};

use crate::harness::field::{be_bytes, decimal, random};

pub fn be(value: Field) -> [u8; 32] {
    be_bytes(&decimal(value))
}

pub fn from_be(bytes: &[u8; 32]) -> Field {
    Field::from(Fr::from_be_bytes_mod_order(bytes))
}

pub fn poseidon(inputs: &[Field]) -> Result<Field, HasherError> {
    let bytes: Vec<[u8; 32]> = inputs.iter().map(|input| be(*input)).collect();
    let slices: Vec<&[u8]> = bytes.iter().map(|input| input.as_slice()).collect();
    Poseidon::hashv(&slices).map(|hash| from_be(&hash))
}

pub fn nonzero_hash_chain(values: &[Field]) -> Field {
    let zero = Field::from(0u64);
    values
        .iter()
        .filter(|value| **value != zero)
        .fold(zero, |chain, value| {
            poseidon(&[chain, *value]).expect("a two-input hash")
        })
}

pub fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}
