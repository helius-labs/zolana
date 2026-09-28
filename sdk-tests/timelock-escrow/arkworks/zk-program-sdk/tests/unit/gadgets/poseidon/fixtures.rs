use std::ops::RangeInclusive;

use zk_program_sdk::{
    circuit::{constant, poseidon, value, Assert, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::fixture::{outcome, rule_broken, Fixture, Refusal, Visit};

pub const RULE: &str = "the hash is the poseidon hash of the inputs";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

pub const SUPPORTED: RangeInclusive<usize> = 1..=12;

/// The Poseidon partial round count of each supported arity, from the circom
/// parameters (`N_ROUNDS_P` in circomlib's `poseidon.circom`); every arity has
/// 8 full rounds over a state of arity + 1 elements.
pub const PARTIAL_ROUNDS: [usize; 12] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65];

pub type Hashed = Result<Field, Refusal>;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct PoseidonClaim<const N: usize> {
    pub inputs: [Field; N],
    pub hash: Field,
}

impl<const N: usize> Fixture<Hashed> for PoseidonClaim<N> {
    fn computed(circuit: &PoseidonClaimCircuit<N>) -> Hashed {
        outcome(poseidon(&circuit.inputs).and_then(|hash| value(&hash)))
    }
}

impl<const N: usize> Constraints for PoseidonClaimCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        poseidon(&self.inputs)?.assert_equal(&self.hash, RULE)
    }
}

pub fn fixture<const N: usize>(inputs: &[Field], hash: Field) -> PoseidonClaim<N> {
    PoseidonClaim {
        inputs: inputs.try_into().expect("the fixture's arity"),
        hash,
    }
}

/// Visits the `PoseidonClaim` of `inputs.len()` inputs: every supported arity,
/// and 0 and 13 just outside them.
pub fn claim<V: Visit<Hashed>>(visitor: &V, inputs: &[Field], hash: Field) -> V::Output {
    match inputs.len() {
        0 => visitor.visit(&fixture::<0>(inputs, hash)),
        1 => visitor.visit(&fixture::<1>(inputs, hash)),
        2 => visitor.visit(&fixture::<2>(inputs, hash)),
        3 => visitor.visit(&fixture::<3>(inputs, hash)),
        4 => visitor.visit(&fixture::<4>(inputs, hash)),
        5 => visitor.visit(&fixture::<5>(inputs, hash)),
        6 => visitor.visit(&fixture::<6>(inputs, hash)),
        7 => visitor.visit(&fixture::<7>(inputs, hash)),
        8 => visitor.visit(&fixture::<8>(inputs, hash)),
        9 => visitor.visit(&fixture::<9>(inputs, hash)),
        10 => visitor.visit(&fixture::<10>(inputs, hash)),
        11 => visitor.visit(&fixture::<11>(inputs, hash)),
        12 => visitor.visit(&fixture::<12>(inputs, hash)),
        13 => visitor.visit(&fixture::<13>(inputs, hash)),
        arity => panic!("no PoseidonClaim of arity {arity}"),
    }
}

/// A check written once over `PoseidonClaim<N>` and run at every supported
/// arity.
pub trait PerArity {
    type Output;

    fn at<const N: usize>(&self) -> Self::Output;
}

/// Runs `check` at every supported arity, each on its own thread: the
/// external checks spend seconds per circom witness calculation.
pub fn every_arity<P: PerArity + Sync>(check: &P) -> Vec<(usize, P::Output)>
where
    P::Output: Send,
{
    std::thread::scope(|scope| {
        let runs = [
            scope.spawn(|| check.at::<1>()),
            scope.spawn(|| check.at::<2>()),
            scope.spawn(|| check.at::<3>()),
            scope.spawn(|| check.at::<4>()),
            scope.spawn(|| check.at::<5>()),
            scope.spawn(|| check.at::<6>()),
            scope.spawn(|| check.at::<7>()),
            scope.spawn(|| check.at::<8>()),
            scope.spawn(|| check.at::<9>()),
            scope.spawn(|| check.at::<10>()),
            scope.spawn(|| check.at::<11>()),
            scope.spawn(|| check.at::<12>()),
        ];
        SUPPORTED
            .zip(runs)
            .map(|(arity, run)| (arity, run.join().expect("an arity's check")))
            .collect()
    })
}

/// The arity's first inputs 1, 2, ..., arity.
pub fn counting(arity: usize) -> Vec<Field> {
    (1..=arity as u64).map(Field::from).collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantInputs {
    pub hash: Field,
}

impl Constraints for ConstantInputsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        poseidon(&[constant(1u64), constant(2u64)])?.assert_equal(&self.hash, RULE)
    }
}
