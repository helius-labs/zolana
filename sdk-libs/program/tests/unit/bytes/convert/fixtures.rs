use zolana_program::{
    circuit::{self, Assert, CircuitVar, Constraints, Field},
    conversion::ProofInput,
    Bytes, CircuitError,
};

use super::vectors::Pair;
use crate::harness::fixture::{rule_broken, Fixture, Refusal, Visit, Visited};

pub const SPLIT_RULE: &str = "the bytes are the value's big-endian bytes";
pub const PACK_RULE: &str = "the packed value is the bytes read big-endian";
pub const FILE: &str = file!();

pub const SPLIT_BROKEN: Refusal = rule_broken(SPLIT_RULE, FILE);
pub const PACK_BROKEN: Refusal = rule_broken(PACK_RULE, FILE);

pub const SPLIT_FORMS: [&str; 2] = ["Bytes::try_from(&var)", "Bytes::try_from(var)"];
pub const PACK_FORMS: [&str; 2] = [
    "CircuitVar::try_from(&bytes)",
    "CircuitVar::try_from(bytes)",
];

pub fn split<const N: usize, const FORM: usize>(
    var: &CircuitVar,
) -> Result<circuit::Bytes<N>, CircuitError> {
    match FORM {
        0 => circuit::Bytes::try_from(var),
        _ => circuit::Bytes::try_from(var.clone()),
    }
}

pub fn pack<const N: usize, const FORM: usize>(
    bytes: &circuit::Bytes<N>,
) -> Result<CircuitVar, CircuitError> {
    match FORM {
        0 => CircuitVar::try_from(bytes),
        _ => CircuitVar::try_from(bytes.clone()),
    }
}

/// The name, message and file of an error.
pub type Failure = (&'static str, String, &'static str);

pub fn failure(error: CircuitError) -> Failure {
    (error.name(), error.to_string(), error.location().file())
}

/// The bytes a fixture computes natively, or why computing them fails.
pub type Computed = Result<Vec<CircuitVar>, Failure>;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Allocated<const N: usize> {
    pub bytes: Bytes<N>,
}

impl<const N: usize> Constraints for AllocatedCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        Ok(())
    }
}

impl<const N: usize> Fixture<Computed> for Allocated<N> {
    fn computed(circuit: &AllocatedCircuit<N>) -> Computed {
        Ok(circuit.bytes.bytes().to_vec())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Split<const N: usize, const FORM: usize> {
    pub value: Field,
    pub bytes: [Field; N],
}

impl<const N: usize, const FORM: usize> Constraints for SplitCircuit<N, FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        split::<N, FORM>(&self.value)?
            .bytes()
            .assert_equal(&self.bytes, SPLIT_RULE)
    }
}

impl<const N: usize, const FORM: usize> Fixture<Computed> for Split<N, FORM> {
    fn computed(circuit: &SplitCircuit<N, FORM>) -> Computed {
        split::<N, FORM>(&circuit.value)
            .map(|bytes| bytes.bytes().to_vec())
            .map_err(failure)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Pack<const N: usize, const FORM: usize> {
    pub bytes: Bytes<N>,
    pub packed: Field,
}

impl<const N: usize, const FORM: usize> Constraints for PackCircuit<N, FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        pack::<N, FORM>(&self.bytes)?.assert_equal(&self.packed, PACK_RULE)
    }
}

impl<const N: usize, const FORM: usize> Fixture<Computed> for Pack<N, FORM> {
    fn computed(circuit: &PackCircuit<N, FORM>) -> Computed {
        pack::<N, FORM>(&circuit.bytes)
            .map(|packed| vec![packed])
            .map_err(failure)
    }
}

pub fn split_fixture<const N: usize, const FORM: usize>(pair: &Pair) -> Split<N, FORM> {
    Split {
        value: pair.value,
        bytes: pair.array::<N>().map(Field::from),
    }
}

pub fn pack_fixture<const N: usize, const FORM: usize>(pair: &Pair) -> Pack<N, FORM> {
    Pack {
        bytes: Bytes(pair.array::<N>()),
        packed: pair.value,
    }
}

fn split_forms_of<const N: usize, V: Visit<Computed>>(
    visitor: &V,
    pair: &Pair,
) -> Visited<V::Output> {
    SPLIT_FORMS
        .into_iter()
        .zip([
            visitor.visit(&split_fixture::<N, 0>(pair)),
            visitor.visit(&split_fixture::<N, 1>(pair)),
        ])
        .collect()
}

fn pack_forms_of<const N: usize, V: Visit<Computed>>(
    visitor: &V,
    pair: &Pair,
) -> Visited<V::Output> {
    PACK_FORMS
        .into_iter()
        .zip([
            visitor.visit(&pack_fixture::<N, 0>(pair)),
            visitor.visit(&pack_fixture::<N, 1>(pair)),
        ])
        .collect()
}

/// Every split form of the pair's width.
pub fn split_forms<V: Visit<Computed>>(visitor: &V, pair: &Pair) -> Visited<V::Output> {
    match pair.width() {
        0 => split_forms_of::<0, V>(visitor, pair),
        1 => split_forms_of::<1, V>(visitor, pair),
        2 => split_forms_of::<2, V>(visitor, pair),
        31 => split_forms_of::<31, V>(visitor, pair),
        32 => split_forms_of::<32, V>(visitor, pair),
        width => panic!("no split fixture of width {width}"),
    }
}

/// Every pack form of the pair's width.
pub fn pack_forms<V: Visit<Computed>>(visitor: &V, pair: &Pair) -> Visited<V::Output> {
    match pair.width() {
        0 => pack_forms_of::<0, V>(visitor, pair),
        1 => pack_forms_of::<1, V>(visitor, pair),
        2 => pack_forms_of::<2, V>(visitor, pair),
        31 => pack_forms_of::<31, V>(visitor, pair),
        32 => pack_forms_of::<32, V>(visitor, pair),
        width => panic!("no pack fixture of width {width}"),
    }
}

fn allocated_of<const N: usize, V: Visit<Computed>>(visitor: &V, pair: &Pair) -> V::Output {
    visitor.visit(&Allocated::<N> {
        bytes: Bytes(pair.array()),
    })
}

/// The allocation fixture of the pair's bytes.
pub fn allocated<V: Visit<Computed>>(visitor: &V, pair: &Pair) -> V::Output {
    match pair.width() {
        0 => allocated_of::<0, V>(visitor, pair),
        1 => allocated_of::<1, V>(visitor, pair),
        2 => allocated_of::<2, V>(visitor, pair),
        31 => allocated_of::<31, V>(visitor, pair),
        32 => allocated_of::<32, V>(visitor, pair),
        width => panic!("no allocation fixture of width {width}"),
    }
}

/// Builds constant bytes in the circuit and asserts nothing about them.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Constants;

impl Constraints for ConstantsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let bytes = circuit::Bytes::constant(&[1, 2, 255]);
        drop(CircuitVar::try_from(&bytes)?);
        drop(circuit::Bytes::<3>::try_from(&circuit::constant(
            66_051u64,
        ))?);
        drop(circuit::Bytes::<32>::default());
        Ok(())
    }
}
