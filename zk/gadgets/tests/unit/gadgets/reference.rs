//! The native reference the gadgets are checked against: `zolana_hasher`'s
//! Poseidon.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use proptest::prelude::*;
use zolana_hasher::{Hasher, HasherError, Poseidon};
use zolana_program::circuit::Field;

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

pub fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}
