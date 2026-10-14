use zolana_program::{
    circuit::{constant, nonzero_hash_chain, value, Assert, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::{
    gadgets::reference,
    harness::fixture::{outcome, rule_broken, Fixture, Refusal, Visit},
};

pub const RULE: &str = "the chain is the hash chain of the nonzero values";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

pub type Chained = Result<Field, Refusal>;

/// The protocol's nonzero hash chain over `zolana_hasher`'s Poseidon: zero
/// values are skipped, the first nonzero value is the chain as it is, and every
/// later nonzero value folds in as `Poseidon(chain, value)`.
pub fn reference_chain(values: &[Field]) -> Field {
    let zero = Field::from(0u64);
    values
        .iter()
        .filter(|value| **value != zero)
        .fold(zero, |chain, value| {
            if chain == zero {
                *value
            } else {
                reference::poseidon(&[chain, *value]).expect("a two-input hash")
            }
        })
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Chain<const N: usize> {
    pub values: [Field; N],
    pub chain: Field,
}

impl<const N: usize> Fixture<Chained> for Chain<N> {
    fn computed(circuit: &ChainCircuit<N>) -> Chained {
        outcome(nonzero_hash_chain(&circuit.values).and_then(|chain| value(&chain)))
    }
}

impl<const N: usize> Constraints for ChainCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        nonzero_hash_chain(&self.values)?.assert_equal(&self.chain, RULE)
    }
}

pub fn fixture<const N: usize>(values: &[Field], chain: Field) -> Chain<N> {
    Chain {
        values: values.try_into().expect("the fixture's length"),
        chain,
    }
}

/// Visits the `Chain` of `values.len()` values, 0 to 4.
pub fn chain<V: Visit<Chained>>(visitor: &V, values: &[Field], chain: Field) -> V::Output {
    match values.len() {
        0 => visitor.visit(&fixture::<0>(values, chain)),
        1 => visitor.visit(&fixture::<1>(values, chain)),
        2 => visitor.visit(&fixture::<2>(values, chain)),
        3 => visitor.visit(&fixture::<3>(values, chain)),
        4 => visitor.visit(&fixture::<4>(values, chain)),
        len => panic!("no Chain of {len} values"),
    }
}

/// A chain over a zero and two nonzero values fixed in the circuit, asserted
/// against a claimed chain: the zero is skipped, the first nonzero value is
/// taken as it is and the second folds in with one Poseidon.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantValues {
    pub chain: Field,
}

impl Constraints for ConstantValuesCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        nonzero_hash_chain(&[constant(0u64), constant(1u64), constant(2u64)])?
            .assert_equal(&self.chain, RULE)
    }
}
