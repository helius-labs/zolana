use ark_bn254::Fr;
use zk_program_sdk::circuit::{constant, nonzero_hash_chain, CircuitVar, Field};

use super::{
    fixtures::{chain, Chained, RULE_BROKEN},
    vectors::{INVALID, VALID},
};
use crate::{
    gadgets::reference,
    harness::fixture::{native_circuit, per_vector, Fixture, Native, Visit},
};

struct NativeChain;

impl Visit<Chained> for NativeChain {
    type Output = Chained;

    fn visit<F: Fixture<Chained>>(&self, fixture: &F) -> Chained {
        F::computed(&native_circuit(fixture).expect("native instantiation"))
    }
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
fn the_native_chain_is_the_pinned_chain_and_the_native_fold() {
    assert_eq!(
        per_vector(&VALID, |vector| (
            chain(&NativeChain, &vector.values(), Field::from(0u64)),
            reference::nonzero_hash_chain(&vector.values())
        )),
        per_vector(&VALID, |vector| (Ok(vector.chain()), vector.chain()))
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
