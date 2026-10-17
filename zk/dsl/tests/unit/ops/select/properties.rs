use proptest::prelude::*;
use zolana_program::circuit::{value, CircuitVar, Field};

use super::{
    fixtures::{every_form, form_names, ArraySelected, RULE},
    vectors::LENGTH,
};
use crate::harness::{
    field::random,
    fixture::{
        breaks_rule, check_constraints, check_tampered, each, native_circuit, Fixture,
        ProverRefusal, Visit,
    },
};

const SELECTED_WIRE: usize = 4;

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

struct NativeSelected;

impl Visit<CircuitVar> for NativeSelected {
    type Output = Field;

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Field {
        let circuit = native_circuit(fixture).expect("native instantiation");
        value(&F::computed(&circuit)).expect("constant selection")
    }
}

struct Checked(Field);

impl<C> Visit<C> for Checked {
    type Output = (Option<usize>, Result<(), ProverRefusal>);

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        (
            check_constraints(fixture).ok(),
            check_tampered(fixture, SELECTED_WIRE, self.0),
        )
    }
}

proptest! {
    #[test]
    fn natively_every_form_selects_exactly_the_chosen_branch(
        condition in any::<bool>(),
        if_true in arbitrary_field(),
        if_false in arbitrary_field(),
    ) {
        let chosen = if condition { if_true } else { if_false };
        prop_assert_eq!(
            every_form(&NativeSelected, (condition, if_true, if_false, chosen)),
            each(&form_names(), chosen)
        );
    }

    #[test]
    fn every_honest_selection_checks_three_rows_and_every_other_value_breaks_the_claim(
        condition in any::<bool>(),
        if_true in arbitrary_field(),
        if_false in arbitrary_field(),
        offset in arbitrary_field().prop_filter("a wrong selection", |offset| *offset != Field::from(0u64)),
    ) {
        let chosen = if condition { if_true } else { if_false };
        prop_assert_eq!(
            every_form(&Checked(chosen + offset), (condition, if_true, if_false, chosen)),
            each(&form_names(), (Some(3), Err(breaks_rule(2, RULE))))
        );
    }

    #[test]
    fn natively_the_array_select_is_the_chosen_array(
        condition in any::<bool>(),
        if_true in proptest::array::uniform3(arbitrary_field()),
        if_false in proptest::array::uniform3(arbitrary_field()),
    ) {
        let chosen: [Field; LENGTH] = if condition { if_true } else { if_false };
        let fixture = ArraySelected::<LENGTH> { condition, if_true, if_false, selected: chosen };
        let circuit = native_circuit(&fixture).expect("native instantiation");
        let selected = <ArraySelected<LENGTH> as Fixture<[CircuitVar; LENGTH]>>::computed(&circuit)
            .map(|selected| value(&selected).expect("constant selection"));
        prop_assert_eq!((selected, check_constraints(&fixture)), (chosen, Ok(7)));
    }
}
