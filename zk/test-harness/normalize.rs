use std::collections::BTreeMap;

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};

use super::iden3::{R1cs, Row};

pub type Terms = Vec<(usize, Fr)>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Constraint {
    Linear(Terms),
    Quadratic { a: Terms, b: Terms, c: Terms },
}

pub fn constraints(r1cs: &R1cs) -> Vec<Constraint> {
    let mut constraints: Vec<Constraint> =
        r1cs.rows().map(|(a, b, c)| normalize(a, b, c)).collect();
    constraints.sort();
    constraints
}

pub fn normalize(a: &Row, b: &Row, c: &Row) -> Constraint {
    let (a, b, c) = (terms(a), terms(b), terms(c));
    match (constant(&a), constant(&b)) {
        (Some(factor), _) => Constraint::Linear(monic(difference(&b, factor, &c)).1),
        (None, Some(factor)) => Constraint::Linear(monic(difference(&a, factor, &c)).1),
        (None, None) => {
            let (a_lead, a) = monic(a);
            let (b_lead, b) = monic(b);
            let inverse = (a_lead * b_lead).inverse().expect("nonzero leads");
            let c = scaled(&c, inverse);
            let (a, b) = if a <= b { (a, b) } else { (b, a) };
            Constraint::Quadratic { a, b, c }
        }
    }
}

fn terms(row: &Row) -> Terms {
    let mut combined = BTreeMap::new();
    for (coefficient, variable) in row {
        *combined.entry(*variable).or_insert_with(Fr::zero) += coefficient;
    }
    combined
        .into_iter()
        .filter(|(_, coefficient)| !coefficient.is_zero())
        .collect()
}

fn constant(terms: &Terms) -> Option<Fr> {
    match terms.as_slice() {
        [] => Some(Fr::zero()),
        [(0, value)] => Some(*value),
        _ => None,
    }
}

fn difference(scaled_row: &Terms, factor: Fr, subtracted: &Terms) -> Terms {
    let pairs: Row = scaled(scaled_row, factor)
        .into_iter()
        .chain(scaled(subtracted, -Fr::one()))
        .map(|(variable, coefficient)| (coefficient, variable))
        .collect();
    terms(&pairs)
}

fn scaled(terms: &Terms, factor: Fr) -> Terms {
    terms
        .iter()
        .map(|(variable, coefficient)| (*variable, *coefficient * factor))
        .filter(|(_, coefficient)| !coefficient.is_zero())
        .collect()
}

fn monic(terms: Terms) -> (Fr, Terms) {
    match terms.first() {
        Some((_, lead)) => {
            let lead = *lead;
            (lead, scaled(&terms, lead.inverse().expect("nonzero lead")))
        }
        None => (Fr::one(), terms),
    }
}
