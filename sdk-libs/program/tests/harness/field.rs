use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use zolana_program::circuit::Field;

pub const MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
pub const MODULUS_MINUS_1: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";
pub const MODULUS_MINUS_2: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495615";
pub const HALF_BELOW: &str =
    "10944121435919637611123202872628637544274182200208017171849102093287904247808";
pub const HALF_ABOVE: &str =
    "10944121435919637611123202872628637544274182200208017171849102093287904247809";
pub const TWO_POW_64_MINUS_1: &str = "18446744073709551615";
pub const TWO_POW_64: &str = "18446744073709551616";
pub const TWO_POW_253: &str =
    "14474011154664524427946373126085988481658748083205070504932198000989141204992";

pub fn modulus() -> BigUint {
    BigUint::from(Fr::MODULUS)
}

pub fn integer(decimal: &str) -> BigUint {
    BigUint::parse_bytes(decimal.as_bytes(), 10).expect("decimal integer")
}

pub fn canonical(decimal: &str) -> Option<Fr> {
    let value = integer(decimal);
    (value < modulus()).then(|| Fr::from(value))
}

pub fn fr(decimal: &str) -> Fr {
    canonical(decimal).expect("canonical field element")
}

pub fn field(decimal: &str) -> Field {
    Field::from(fr(decimal))
}

pub fn decimal(value: Field) -> String {
    BigUint::from(Fr::from(value).into_bigint()).to_string()
}

pub fn be_bytes(decimal: &str) -> [u8; 32] {
    let bytes = integer(decimal).to_bytes_be();
    let mut padded = [0u8; 32];
    padded
        .get_mut(32 - bytes.len()..)
        .expect("at most 32 bytes")
        .copy_from_slice(&bytes);
    padded
}

pub fn random(bytes: [u8; 32]) -> Field {
    Field::from(Fr::from_le_bytes_mod_order(&bytes))
}
