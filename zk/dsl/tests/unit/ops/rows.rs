use ark_bn254::Fr;
use ark_ff::One;

use crate::harness::iden3::{R1cs, R1csHeader, Row};

pub type Constraint = (Row, Row, Row);

pub fn one() -> Fr {
    Fr::one()
}

pub fn minus_one() -> Fr {
    -Fr::one()
}

/// The row a `bool` proof input adds: `b * (b - 1) = 0`.
pub fn boolean_row(variable: usize) -> Constraint {
    (
        vec![(one(), variable)],
        vec![(minus_one(), 0), (one(), variable)],
        vec![],
    )
}

/// A constraint-only export with the identity label map.
pub fn r1cs(header: R1csHeader, rows: Vec<Constraint>) -> R1cs {
    let wire_labels = (0..u64::try_from(header.variables).expect("label count")).collect();
    let (mut a, mut b, mut c) = (vec![], vec![], vec![]);
    for (row_a, row_b, row_c) in rows {
        a.push(row_a);
        b.push(row_b);
        c.push(row_c);
    }
    R1cs {
        header,
        a,
        b,
        c,
        wire_labels,
    }
}
