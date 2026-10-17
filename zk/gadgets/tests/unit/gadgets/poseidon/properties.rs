use proptest::{collection::vec, prelude::*};
use zolana_program::circuit::Field;

use super::{
    fixtures::{claim, Hashed, RULE, RULE_BROKEN},
    r1cs::{claim_row, hash_wire, SIZES},
};
use crate::{
    gadgets::reference::{self, arbitrary_field},
    harness::fixture::{
        breaks_rule, check_tampered, native_circuit, CheckConstraints, Fixture, Native,
        ProverRefusal, Visit,
    },
};

struct NativeHash;

impl Visit<Hashed> for NativeHash {
    type Output = Hashed;

    fn visit<F: Fixture<Hashed>>(&self, fixture: &F) -> Hashed {
        F::computed(&native_circuit(fixture).expect("native instantiation"))
    }
}

struct TamperHash {
    arity: usize,
    claimed: Field,
}

impl Visit<Hashed> for TamperHash {
    type Output = Result<(), ProverRefusal>;

    fn visit<F: Fixture<Hashed>>(&self, fixture: &F) -> Self::Output {
        check_tampered(fixture, hash_wire(self.arity), self.claimed)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn the_native_hash_is_zolana_hashers_at_every_arity(
        inputs in vec(arbitrary_field(), 1..=12),
    ) {
        prop_assert_eq!(
            claim(&NativeHash, &inputs, Field::from(0u64)),
            Ok(reference::poseidon(&inputs).expect("a supported arity"))
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn the_honest_hash_checks_and_a_wrong_hash_is_refused_natively_and_in_r1cs(
        inputs in vec(arbitrary_field(), 1..=12),
        offset in arbitrary_field().prop_filter("a wrong hash", |offset| *offset != Field::from(0u64)),
    ) {
        let arity = inputs.len();
        let hash = reference::poseidon(&inputs).expect("a supported arity");
        let wrong = hash + offset;
        prop_assert_eq!(
            (
                claim(&CheckConstraints, &inputs, hash),
                claim(&Native, &inputs, wrong),
                claim(&TamperHash { arity, claimed: wrong }, &inputs, hash),
            ),
            (
                Ok(SIZES[arity - 1].constraints),
                Err(RULE_BROKEN),
                Err(breaks_rule(claim_row(arity), RULE)),
            )
        );
    }
}
