use ark_bn254::Fr;
use zolana_program::circuit::{constant, nonzero_hash_chain, value, CircuitVar, Field};

use super::{
    fixtures::{chain, reference_chain, Chained, RULE_BROKEN},
    vectors::{
        shared_vectors, CHAIN_1_2, CHAIN_2_1, FOLD_FROM_ZERO_1_2, INVALID, POSEIDON_0_0,
        POSEIDON_0_1, VALID,
    },
};
use crate::{
    gadgets::reference,
    harness::{
        field::field,
        fixture::{native_circuit, outcome, per_vector, Fixture, Native, Visit},
    },
};

struct NativeChain;

impl Visit<Chained> for NativeChain {
    type Output = Chained;

    fn visit<F: Fixture<Chained>>(&self, fixture: &F) -> Chained {
        F::computed(&native_circuit(fixture).expect("native instantiation"))
    }
}

fn poseidon(inputs: &[Field]) -> Field {
    reference::poseidon(inputs).expect("a two-input hash")
}

#[test]
fn every_valid_vector_holds_natively() {
    assert_eq!(
        per_vector(&VALID, |vector| chain(
            &Native,
            &vector.values(),
            vector.chain()
        )),
        per_vector(&VALID, |_| Ok(()))
    );
}

#[test]
fn every_wrong_chain_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        (
            per_vector(&INVALID, |vector| chain(
                &Native,
                &vector.values(),
                vector.chain()
            )),
            per_vector(&VALID, |vector| chain(
                &Native,
                &vector.values(),
                vector.chain() + Field::from(1u64)
            ))
        ),
        (
            per_vector(&INVALID, |_| Err(RULE_BROKEN)),
            per_vector(&VALID, |_| Err(RULE_BROKEN))
        )
    );
}

#[test]
fn the_native_chain_is_the_pinned_chain_and_the_reference_chain() {
    assert_eq!(
        per_vector(&VALID, |vector| (
            chain(&NativeChain, &vector.values(), Field::from(0u64)),
            reference_chain(&vector.values())
        )),
        per_vector(&VALID, |vector| (Ok(vector.chain()), vector.chain()))
    );
}

#[test]
fn the_pinned_hashes_are_the_poseidon_hashes_they_name() {
    let [zero, one, two] = [0u64, 1, 2].map(Field::from);
    assert_eq!(
        [
            POSEIDON_0_0,
            POSEIDON_0_1,
            CHAIN_1_2,
            CHAIN_2_1,
            FOLD_FROM_ZERO_1_2
        ]
        .map(field),
        [
            poseidon(&[zero, zero]),
            poseidon(&[zero, one]),
            poseidon(&[one, two]),
            poseidon(&[two, one]),
            poseidon(&[poseidon(&[zero, one]), two]),
        ]
    );
}

#[test]
fn the_native_chain_and_the_reference_chain_reproduce_every_shared_vector() {
    let vectors = shared_vectors();
    assert_eq!(
        vectors
            .iter()
            .map(|vector| {
                let values: Vec<CircuitVar> = vector.values.iter().copied().map(constant).collect();
                (
                    vector.name.as_str(),
                    outcome(nonzero_hash_chain(&values).and_then(|chain| value(&chain))),
                    reference_chain(&vector.values),
                )
            })
            .collect::<Vec<_>>(),
        vectors
            .iter()
            .map(|vector| (vector.name.as_str(), Ok(vector.chain), vector.chain))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_chain_of_constants_is_a_constant() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let values: Vec<CircuitVar> = vector.values().into_iter().map(constant).collect();
            nonzero_hash_chain(&values)
                .map(|chain| format!("{chain:?}"))
                .ok()
        }),
        per_vector(&VALID, |vector| Some(format!(
            "CircuitVar::constant({})",
            Fr::from(vector.chain())
        )))
    );
}
