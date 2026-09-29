use ark_bn254::Fr;
use ark_ff::One;

use crate::{
    harness::field::{fr, MODULUS_MINUS_1},
    uint::rows::{max, power_of_two},
};

pub const WIDTHS: [u32; 5] = [1, 4, 64, 252, 253];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub x: Fr,
}

pub fn valid(bits: u32) -> Vec<Vector> {
    vec![
        Vector {
            name: "0",
            x: Fr::from(0u64),
        },
        Vector {
            name: "1",
            x: Fr::one(),
        },
        Vector {
            name: "2^BITS - 1",
            x: max(bits),
        },
    ]
}

pub fn invalid(bits: u32) -> Vec<Vector> {
    vec![
        Vector {
            name: "2^BITS",
            x: power_of_two(bits),
        },
        Vector {
            name: "2^BITS + 1",
            x: power_of_two(bits) + Fr::one(),
        },
        Vector {
            name: "p - 1",
            x: fr(MODULUS_MINUS_1),
        },
    ]
}
