use ark_bn254::Fr;
use ark_ff::{One, Zero};
use num_bigint::BigUint;
use zolana_program::circuit::Field;

use crate::harness::iden3::{R1cs, R1csHeader, Row};

pub const BYTE_RULE: &str = "a byte proof input does not fit in 8 bits";

pub fn array<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex)
        .expect("hex bytes")
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("{} bytes, not {N}", bytes.len()))
}

pub fn fields<const N: usize>(bytes: &[u8; N]) -> [Field; N] {
    bytes.map(Field::from)
}

#[cfg(feature = "external-tools")]
pub fn decimals(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(u8::to_string).collect()
}

pub fn packed(bytes: &[u8]) -> Field {
    Field::from(Fr::from(BigUint::from_bytes_be(bytes)))
}

/// `2^power` as a field element.
pub fn power_of_two(power: usize) -> Fr {
    (0..power).fold(Fr::one(), |weight, _| weight + weight)
}

/// `bit * (1 - bit) = 0`, the booleanity row of a bit arkworks allocates.
pub fn boolean_row(bit: usize) -> (Row, Row, Row) {
    let one = Fr::one();
    (vec![(one, 0), (-one, bit)], vec![(one, bit)], vec![])
}

/// `bits - var = 0` with the `count` bits from wire `first_bit` weighted
/// `2^0, 2^1, ...`, and `var` below the bits.
pub fn recomposition_row(var: usize, first_bit: usize, count: usize) -> (Row, Row, Row) {
    let one = Fr::one();
    let bits = (0..count).map(|index| (power_of_two(index), first_bit + index));
    (
        std::iter::once((-one, var)).chain(bits).collect(),
        vec![(one, 0)],
        vec![],
    )
}

/// The nine rows that range-check the byte at `byte` to 8 bits, its bits in
/// the eight wires after it.
pub fn byte_rows(byte: usize) -> Rows {
    (byte + 1..byte + 9)
        .map(boolean_row)
        .chain([recomposition_row(byte, byte + 1, 8)])
        .collect()
}

pub type Rows = Vec<(Row, Row, Row)>;

/// The export of a constraint-only circuit with these rows over `variables`
/// variables, every private one a private input.
pub fn golden(variables: usize, rows: Rows) -> R1cs {
    let constraints = rows.len();
    let (a, (b, c)) = rows.into_iter().map(|(a, b, c)| (a, (b, c))).unzip();
    R1cs {
        header: R1csHeader::bn254(variables, 0, variables - 1, constraints),
        a,
        b,
        c,
        wire_labels: (0..).take(variables).collect(),
    }
}

/// Every row the witness leaves unsatisfied, not only the first.
pub fn unsatisfied_rows(r1cs: &R1cs, witness: &[Fr]) -> Vec<usize> {
    let evaluate = |row: &Row| {
        row.iter().fold(Fr::zero(), |sum, (coefficient, wire)| {
            sum + *coefficient * witness.get(*wire).expect("row wire")
        })
    };
    r1cs.rows()
        .enumerate()
        .filter(|(_, (a, b, c))| evaluate(a) * evaluate(b) != evaluate(c))
        .map(|(row, _)| row)
        .collect()
}

/// The 8 bits of `value` below 2^8, least significant first.
pub fn low_bits(value: u8) -> [Fr; 8] {
    std::array::from_fn(|bit| Fr::from(u64::from((value >> bit) & 1)))
}
