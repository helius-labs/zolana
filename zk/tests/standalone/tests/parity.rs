//! Rebuilds DSL primitives in a crate outside the DSL, on its public API only,
//! and pins that they export the same R1CS as the built-ins: a gadget author
//! has what the SDK has.

extern crate zolana_zk_dsl as zolana_program;

use zolana_zk_dsl::{
    circuit::{system_of, zero, Assert, Bool, Circuit, CircuitVar, Field, Scope, U64},
    conversion::ProofInput,
    CircuitError, ZkCircuit,
};

const RULE: &str = "the claim is the result";

/// circomlib's `LessThan(64)`: `a < b` is the top bit of `b - a - 1 + 2^64`
/// decomposed into 65 bits.
fn less_than(a: &U64, b: &U64) -> Result<Bool, CircuitError> {
    let shifted =
        CircuitVar::from(b.clone()) - CircuitVar::from(a.clone()) + Field::from(u128::MAX >> 64);
    let _scope = Scope::open(&system_of([&shifted]), "a comparison");
    let bits = shifted.to_bits_le::<65>()?;
    match bits.last() {
        Some(top) => Ok(top.clone()),
        None => Err(CircuitError::rule_broken(
            "a 65-bit decomposition has a top bit",
        )),
    }
}

/// circomlib's `IsZero`.
fn is_zero(value: &U64) -> Result<Bool, CircuitError> {
    CircuitVar::from(value.clone()).is_equal(&zero())
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct BuiltinLessThan {
    a: u64,
    b: u64,
    claim: bool,
}

impl Circuit for BuiltinLessThanCircuit {
    type Output = ();

    fn circuit(&self) -> Result<(), CircuitError> {
        self.a
            .is_less_than(&self.b)?
            .assert_equal(&self.claim, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct ExternalLessThan {
    a: u64,
    b: u64,
    claim: bool,
}

impl Circuit for ExternalLessThanCircuit {
    type Output = ();

    fn circuit(&self) -> Result<(), CircuitError> {
        less_than(&self.a, &self.b)?.assert_equal(&self.claim, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct BuiltinIsZero {
    value: u64,
    claim: bool,
}

impl Circuit for BuiltinIsZeroCircuit {
    type Output = ();

    fn circuit(&self) -> Result<(), CircuitError> {
        self.value.is_zero()?.assert_equal(&self.claim, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct ExternalIsZero {
    value: u64,
    claim: bool,
}

impl Circuit for ExternalIsZeroCircuit {
    type Output = ();

    fn circuit(&self) -> Result<(), CircuitError> {
        is_zero(&self.value)?.assert_equal(&self.claim, RULE)
    }
}

#[test]
fn an_external_less_than_exports_the_built_in_r1cs() {
    assert_eq!(
        ExternalLessThan::export_r1cs().expect("external r1cs"),
        BuiltinLessThan::export_r1cs().expect("built-in r1cs")
    );
}

#[test]
fn an_external_less_than_accepts_and_refuses_like_the_built_in() {
    for (a, b) in [(3, 4), (4, 4), (5, 4), (0, u64::MAX), (u64::MAX, 0)] {
        let claim = a < b;
        let external = ExternalLessThan { a, b, claim };
        let builtin = BuiltinLessThan { a, b, claim };
        assert!(external.check_constraints().is_ok(), "{a} < {b}");
        assert!(builtin.check_constraints().is_ok(), "{a} < {b}");
        let wrong = ExternalLessThan {
            claim: !claim,
            ..external
        };
        assert_eq!(
            wrong
                .check_constraints()
                .map_err(|error| error.broken_rule()),
            Err(Some(RULE)),
            "{a} < {b}"
        );
    }
}

#[test]
fn an_external_is_zero_exports_the_built_in_r1cs() {
    assert_eq!(
        ExternalIsZero::export_r1cs().expect("external r1cs"),
        BuiltinIsZero::export_r1cs().expect("built-in r1cs")
    );
}

#[test]
fn an_external_is_zero_accepts_and_refuses_like_the_built_in() {
    for value in [0, 1, u64::MAX] {
        let claim = value == 0;
        assert!(ExternalIsZero { value, claim }.check_constraints().is_ok());
        assert!(BuiltinIsZero { value, claim }.check_constraints().is_ok());
        assert_eq!(
            ExternalIsZero {
                value,
                claim: !claim
            }
            .check_constraints()
            .map_err(|error| error.broken_rule()),
            Err(Some(RULE))
        );
    }
}
