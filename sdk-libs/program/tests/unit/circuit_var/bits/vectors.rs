use zolana_program::circuit::Field;

use crate::harness::{
    field::{field, HALF_ABOVE, MODULUS_MINUS_1, TWO_POW_253, TWO_POW_64},
    fixture::Named,
};

pub const TWO_POW_252: &str =
    "7237005577332262213973186563042994240829374041602535252466099000494570602496";
pub const TWO_POW_253_MINUS_1: &str =
    "14474011154664524427946373126085988481658748083205070504932198000989141204991";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub x: &'static str,
    pub holds: bool,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn field(&self) -> Field {
        field(self.x)
    }
}

const fn vector(name: &'static str, x: &'static str, holds: bool) -> Vector {
    Vector { name, x, holds }
}

pub const WIDTH_1: [Vector; 4] = [
    vector("0 fits 1 bit", "0", true),
    vector("1 fits 1 bit", "1", true),
    vector("2 does not fit 1 bit", "2", false),
    vector("p - 1 does not fit 1 bit", MODULUS_MINUS_1, false),
];

pub const WIDTH_4: [Vector; 7] = [
    vector("0 fits 4 bits", "0", true),
    vector("1 fits 4 bits", "1", true),
    vector("15 fits 4 bits", "15", true),
    vector("16 does not fit 4 bits", "16", false),
    vector("255 does not fit 4 bits", "255", false),
    vector("2^64 does not fit 4 bits", TWO_POW_64, false),
    vector("p - 1 does not fit 4 bits", MODULUS_MINUS_1, false),
];

pub const WIDTH_253: [Vector; 5] = [
    vector("0 fits 253 bits", "0", true),
    vector("2^252 fits 253 bits", TWO_POW_252, true),
    vector("2^253 - 1 fits 253 bits", TWO_POW_253_MINUS_1, true),
    vector("2^253 does not fit 253 bits", TWO_POW_253, false),
    vector("p - 1 does not fit 253 bits", MODULUS_MINUS_1, false),
];

pub const BOOL: [Vector; 5] = [
    vector("0 is a bool", "0", true),
    vector("1 is a bool", "1", true),
    vector("2 is not a bool", "2", false),
    vector("(p + 1) / 2 is not a bool", HALF_ABOVE, false),
    vector("p - 1 is not a bool", MODULUS_MINUS_1, false),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitsVector {
    pub name: &'static str,
    pub bits: [u64; 4],
    pub value: u64,
    pub holds: bool,
}

impl Named for BitsVector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl BitsVector {
    pub fn bits(&self) -> [Field; 4] {
        self.bits.map(Field::from)
    }

    pub fn value(&self) -> Field {
        Field::from(self.value)
    }
}

const fn bits(name: &'static str, bits: [u64; 4], value: u64, holds: bool) -> BitsVector {
    BitsVector {
        name,
        bits,
        value,
        holds,
    }
}

pub const BITS_4: [BitsVector; 8] = [
    bits("0000 is 0", [0, 0, 0, 0], 0, true),
    bits("1010 is 5", [1, 0, 1, 0], 5, true),
    bits("0001 is 8", [0, 0, 0, 1], 8, true),
    bits("1111 is 15", [1, 1, 1, 1], 15, true),
    bits("1010 is not 6", [1, 0, 1, 0], 6, false),
    bits("0101 is not 5", [0, 1, 0, 1], 5, false),
    bits("1111 is not 16", [1, 1, 1, 1], 16, false),
    bits("3100 sums to 5 with a bit of 3", [3, 1, 0, 0], 5, false),
];
