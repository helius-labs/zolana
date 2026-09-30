use super::{
    fixtures::{decoded, selected, OneHot, SelectIndex, FLAG_RULE, SELECT_RULE},
    vectors::{invalid_indices, items},
};
use crate::harness::{field::field, fixture::native};
use zolana_program::circuit::{constant, one_hot, select_index, value, CircuitVar, Field};

#[test]
fn every_valid_index_decodes_and_selects_exactly_its_item() {
    for items in items() {
        for index in 0..3 {
            assert_eq!(native(&decoded::<3>(index)), Ok(()));
            assert_eq!(native(&selected(items, index)), Ok(()));
            let mut wrong = decoded::<3>(index);
            *wrong.flags.get_mut(index).expect("index") = field("0");
            assert_eq!(native(&wrong).unwrap_err().1, Some(FLAG_RULE));
            let mut wrong = selected(items, index);
            wrong.selected = wrong.selected + field("1");
            assert_eq!(native(&wrong).unwrap_err().1, Some(SELECT_RULE));
        }
    }
}

#[test]
fn every_out_of_bounds_index_has_the_named_error() {
    for index in invalid_indices() {
        for refusal in [
            native(&OneHot::<3> {
                index,
                flags: [field("0"); 3],
            }),
            native(&SelectIndex::<3> {
                index,
                items: [field("7"); 3],
                selected: field("7"),
            }),
        ] {
            assert_eq!(refusal.unwrap_err().0, "CircuitError.IndexOutOfBounds");
        }
    }
    assert_eq!(
        native(&OneHot::<0> {
            index: field("0"),
            flags: []
        })
        .unwrap_err()
        .0,
        "CircuitError.IndexOutOfBounds"
    );
    assert_eq!(
        native(&SelectIndex::<0> {
            index: field("0"),
            items: [],
            selected: field("0")
        })
        .unwrap_err()
        .0,
        "CircuitError.IndexOutOfBounds"
    );
    assert_eq!(native(&decoded::<1>(0)), Ok(()));
    assert_eq!(native(&selected([field("7")], 0)), Ok(()));
}

#[test]
fn constant_indices_and_items_compute_the_expected_values() {
    for index in 0..3 {
        let flags = one_hot::<3>(&constant(index as u64)).expect("index");
        let actual: Vec<_> = flags
            .into_iter()
            .map(|flag| value(&CircuitVar::from(flag)).unwrap())
            .collect();
        assert_eq!(actual, decoded::<3>(index).flags);
        assert_eq!(
            value(
                &select_index(
                    &[constant(3u64), constant(5u64), constant(7u64)],
                    &constant(index as u64)
                )
                .unwrap()
            )
            .unwrap(),
            Field::from(3 + 2 * index as u64)
        );
    }
}
