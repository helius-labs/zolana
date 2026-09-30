use zolana_program::circuit::Field;

use crate::{
    bytes::support::packed,
    harness::{
        field::{field, integer, MODULUS_MINUS_1},
        fixture::Named,
    },
};

const TWO_POW_240: &str =
    "1766847064778384329583297500742918515827483896875618958121606201292619776";
const TWO_POW_248_MINUS_1: &str =
    "452312848583266388373324160190187140051835877600158453279131187530910662655";
const TWO_POW_248: &str =
    "452312848583266388373324160190187140051835877600158453279131187530910662656";
const ASCENDING: &str = "1780731860627700044960722568376592200742329637303199754547598369979440671";

const ZEROS_31: &str = "00000000000000000000000000000000000000000000000000000000000000";
const ONES_31: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const TWO_POW_240_BE: &str = "01000000000000000000000000000000000000000000000000000000000000";
const TWO_POW_240_LE: &str = "00000000000000000000000000000000000000000000000000000000000001";
const ASCENDING_BE: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const LOW_31_OF_MODULUS_MINUS_1: &str =
    "644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
const ZEROS_32: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ONE_32: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// A value and N bytes as hex; the width N is the hex length over 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub value: &'static str,
    pub hex: &'static str,
}

impl Named for Vector {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl Vector {
    pub fn width(&self) -> usize {
        self.pair().width()
    }

    pub fn value(&self) -> Field {
        field(self.value)
    }

    pub fn bytes(&self) -> Vec<u8> {
        hex::decode(self.hex).expect("hex bytes")
    }

    pub fn pair(&self) -> Pair {
        Pair {
            value: self.value(),
            bytes: self.bytes(),
        }
    }

    /// The vector's bytes with the value they pack to.
    pub fn packed_pair(&self) -> Pair {
        let bytes = self.bytes();
        Pair {
            value: packed(&bytes),
            bytes,
        }
    }

    /// The vector's value with its own big-endian bytes; the value fits.
    pub fn split_pair(&self) -> Pair {
        let significant: Vec<u8> = integer(self.value)
            .to_bytes_be()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        let padding = self
            .width()
            .checked_sub(significant.len())
            .expect("the value fits");
        let bytes = std::iter::repeat_n(0, padding).chain(significant).collect();
        Pair {
            value: self.value(),
            bytes,
        }
    }
}

/// A value and bytes a fixture claims are the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pair {
    pub value: Field,
    pub bytes: Vec<u8>,
}

impl Pair {
    pub fn width(&self) -> usize {
        self.bytes.len()
    }

    pub fn array<const N: usize>(&self) -> [u8; N] {
        self.bytes
            .clone()
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| panic!("{} bytes, not {N}", bytes.len()))
    }
}

const fn vector(name: &'static str, value: &'static str, hex: &'static str) -> Vector {
    Vector { name, value, hex }
}

/// The bytes are exactly the value's big-endian bytes.
pub const VALID: [Vector; 11] = [
    vector("0 in 0 bytes", "0", ""),
    vector("0 in 1 byte", "0", "00"),
    vector("1 in 1 byte", "1", "01"),
    vector("255 in 1 byte", "255", "ff"),
    vector("0 in 2 bytes", "0", "0000"),
    vector("256 in 2 bytes", "256", "0100"),
    vector("258 in 2 bytes", "258", "0102"),
    vector("65535 in 2 bytes", "65535", "ffff"),
    vector("2^240 in 31 bytes", TWO_POW_240, TWO_POW_240_BE),
    vector("2^248 - 1 in 31 bytes", TWO_POW_248_MINUS_1, ONES_31),
    vector("ascending 31 bytes", ASCENDING, ASCENDING_BE),
];

/// The value fits in N bytes, but the bytes are not its big-endian bytes.
pub const WRONG: [Vector; 5] = [
    vector("1 claimed as 02", "1", "02"),
    vector("258 claimed little-endian", "258", "0201"),
    vector("65535 claimed as fffe", "65535", "fffe"),
    vector("2^240 claimed little-endian", TWO_POW_240, TWO_POW_240_LE),
    vector(
        "ascending 31 bytes claimed as 2^240",
        ASCENDING,
        TWO_POW_240_BE,
    ),
];

/// The value does not fit in N bytes; the bytes are its low 8N bits.
pub const TOO_LARGE: [Vector; 6] = [
    vector("1 in 0 bytes", "1", ""),
    vector("256 in 1 byte", "256", "00"),
    vector("p - 1 in 1 byte", MODULUS_MINUS_1, "00"),
    vector("65536 in 2 bytes", "65536", "0000"),
    vector("2^248 in 31 bytes", TWO_POW_248, ZEROS_31),
    vector(
        "p - 1 in 31 bytes",
        MODULUS_MINUS_1,
        LOW_31_OF_MODULUS_MINUS_1,
    ),
];

/// 32 bytes: wider than one 31-byte chunk.
pub const WIDE: [Vector; 2] = [
    vector("0 in 32 bytes", "0", ZEROS_32),
    vector("1 in 32 bytes", "1", ONE_32),
];
