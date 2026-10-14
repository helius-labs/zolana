use proptest::{collection::vec, prelude::*};
use zolana_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use zolana_program::circuit::Field;

use super::{
    fixtures::{chain, reference_chain, Chained, RULE, RULE_BROKEN},
    r1cs::{chain_wire, claim_row, pinned},
};
use crate::{
    gadgets::reference::{self, arbitrary_field},
    harness::fixture::{
        breaks_rule, check_tampered, native_circuit, CheckConstraints, Fixture, Native,
        ProverRefusal, Visit,
    },
};

fn zero() -> Field {
    Field::from(0u64)
}

fn value_or_zero() -> impl Strategy<Value = Field> {
    prop_oneof![Just(zero()), arbitrary_field()]
}

fn protocol_chain(values: &[Field]) -> Field {
    let elements: Vec<[u8; 32]> = values.iter().map(|value| reference::be(*value)).collect();
    reference::from_be(
        &create_nonzero_hash_chain_from_slice(&elements).expect("a nonzero hash chain"),
    )
}

struct NativeChain;

impl Visit<Chained> for NativeChain {
    type Output = Chained;

    fn visit<F: Fixture<Chained>>(&self, fixture: &F) -> Chained {
        F::computed(&native_circuit(fixture).expect("native instantiation"))
    }
}

struct TamperChain {
    len: usize,
    claimed: Field,
}

impl Visit<Chained> for TamperChain {
    type Output = Result<(), ProverRefusal>;

    fn visit<F: Fixture<Chained>>(&self, fixture: &F) -> Self::Output {
        check_tampered(fixture, chain_wire(self.len), self.claimed)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn the_native_chain_is_the_reference_and_the_protocol_chain_and_ignores_zeros(
        values in vec(value_or_zero(), 0..=4),
    ) {
        let nonzero: Vec<Field> = values.iter().copied().filter(|value| *value != zero()).collect();
        let expected = reference_chain(&values);
        prop_assert_eq!(
            (
                chain(&NativeChain, &values, zero()),
                chain(&NativeChain, &nonzero, zero()),
                protocol_chain(&values),
            ),
            (Ok(expected), Ok(expected), expected)
        );
    }

    #[test]
    fn the_honest_chain_checks_and_a_wrong_chain_is_refused_natively_and_in_r1cs(
        values in vec(value_or_zero(), 0..=4),
        offset in arbitrary_field().prop_filter("a wrong chain", |offset| *offset != zero()),
    ) {
        let len = values.len();
        let honest = reference_chain(&values);
        let wrong = honest + offset;
        prop_assert_eq!(
            (
                chain(&CheckConstraints, &values, honest),
                chain(&Native, &values, wrong),
                chain(&TamperChain { len, claimed: wrong }, &values, honest),
            ),
            (
                Ok(pinned(len).constraints),
                Err(RULE_BROKEN),
                Err(breaks_rule(claim_row(len), RULE)),
            )
        );
    }
}
