use std::collections::BTreeSet;

use ark_bn254::Fr;
use zolana_program::circuit::{constant, poseidon, value, CircuitVar, Field};

use super::{
    fixtures::{claim, Hashed, RULE_BROKEN},
    vectors::{INVALID, VALID},
};
use crate::{
    gadgets::reference,
    harness::{
        field::decimal,
        fixture::{native_circuit, per_vector, Fixture, Native, Refusal, Visit},
    },
};

pub const POSEIDON_FILE: &str = "sdk-libs/program/src/circuit/builtins/gadgets/poseidon.rs";

pub const UNSUPPORTED: Refusal = (
    "CircuitError.UnsupportedHashInputCount",
    None,
    POSEIDON_FILE,
);

struct NativeHash;

impl Visit<Hashed> for NativeHash {
    type Output = Hashed;

    fn visit<F: Fixture<Hashed>>(&self, fixture: &F) -> Hashed {
        F::computed(&native_circuit(fixture).expect("native instantiation"))
    }
}

fn constants(inputs: &[Field]) -> Vec<CircuitVar> {
    inputs.iter().map(|input| constant(*input)).collect()
}

#[test]
fn every_valid_vector_holds_natively() {
    assert_eq!(
        per_vector(&VALID, |vector| claim(
            &Native,
            &vector.inputs(),
            vector.hash()
        )),
        per_vector(&VALID, |_| Ok(()))
    );
}

#[test]
fn every_wrong_claim_breaks_exactly_the_fixture_rule_natively() {
    let off_by_one = per_vector(&VALID, |vector| {
        claim(&Native, &vector.inputs(), vector.hash() + Field::from(1u64))
    });
    assert_eq!(
        (
            per_vector(&INVALID, |vector| claim(
                &Native,
                &vector.inputs(),
                vector.hash()
            )),
            off_by_one
        ),
        (
            per_vector(&INVALID, |_| Err(RULE_BROKEN)),
            per_vector(&VALID, |_| Err(RULE_BROKEN))
        )
    );
}

#[test]
fn the_native_hash_is_the_pinned_hash_and_zolana_hashers_at_every_arity() {
    assert_eq!(
        per_vector(&VALID, |vector| (
            claim(&NativeHash, &vector.inputs(), Field::from(0u64)),
            reference::poseidon(&vector.inputs()).ok()
        )),
        per_vector(&VALID, |vector| (Ok(vector.hash()), Some(vector.hash())))
    );
}

#[test]
fn a_hash_of_constants_is_a_constant() {
    assert_eq!(
        per_vector(&VALID, |vector| poseidon(&constants(&vector.inputs()))
            .map(|hash| format!("{hash:?}"))
            .ok()),
        per_vector(&VALID, |vector| Some(format!(
            "CircuitVar::constant({})",
            Fr::from(vector.hash())
        )))
    );
}

#[test]
fn every_arity_outside_one_to_twelve_is_refused_like_zolana_hashers() {
    let refused = |inputs: usize| {
        let refusal = poseidon(&vec![constant(1u64); inputs])
            .map(|_| ())
            .map_err(|error| (error.name(), error.to_string()));
        let native = reference::poseidon(&vec![Field::from(1u64); inputs]).is_err();
        (inputs, refusal, native)
    };
    let arities = [0, 13, 16, 254, 255, 256, 1000];
    assert_eq!(
        arities.map(refused),
        arities.map(|inputs| (
            inputs,
            Err((
                "CircuitError.UnsupportedHashInputCount",
                format!("a hash over {inputs} inputs is not supported")
            )),
            true
        ))
    );
}

#[test]
fn a_fixture_of_an_unsupported_arity_is_refused_at_the_hash() {
    assert_eq!(
        (
            claim(&Native, &[], Field::from(0u64)),
            claim(&Native, &[Field::from(1u64); 13], Field::from(0u64)),
        ),
        (Err(UNSUPPORTED), Err(UNSUPPORTED))
    );
}

#[test]
fn one_padded_with_zeros_hashes_to_a_distinct_value_at_every_arity() {
    let hashes: Vec<String> = (1..=12)
        .map(|arity| {
            let mut inputs = vec![Field::from(0u64); arity];
            inputs[0] = Field::from(1u64);
            let hash = poseidon(&constants(&inputs)).and_then(|hash| value(&hash));
            decimal(hash.expect("a supported arity"))
        })
        .collect();
    let distinct: BTreeSet<&String> = hashes.iter().collect();
    assert_eq!((hashes.len(), distinct.len()), (12, 12));
}
