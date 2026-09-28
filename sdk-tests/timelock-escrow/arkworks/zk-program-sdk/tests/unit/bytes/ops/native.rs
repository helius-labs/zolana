use super::fixtures::*;
use crate::{bytes::support::fields, harness::fixture::native};
use zk_program_sdk::{
    circuit::{self, value, Assert},
    Bytes,
};

fn check<const N: usize>(left: [u8; N], right: [u8; N]) {
    let equal = left == right;
    assert_eq!(
        native(&AssertEqual {
            left: Bytes(left),
            right: Bytes(right)
        }),
        if equal { Ok(()) } else { Err(EQUAL_BROKEN) }
    );
    assert_eq!(
        native(&AssertNotEqual {
            left: Bytes(left),
            right: Bytes(right)
        }),
        if equal { Err(NOT_EQUAL_BROKEN) } else { Ok(()) }
    );
    for condition in [false, true] {
        assert_eq!(
            native(&AssertEqualIf {
                left: Bytes(left),
                right: Bytes(right),
                condition
            }),
            if !condition || equal {
                Ok(())
            } else {
                Err(EQUAL_IF_BROKEN)
            }
        );
        assert_eq!(
            native(&IsEqual {
                left: Bytes(left),
                right: Bytes(right),
                claimed: condition
            }),
            if condition == equal {
                Ok(())
            } else {
                Err(IS_EQUAL_BROKEN)
            }
        );
        let selected = if condition { left } else { right };
        assert_eq!(
            constant_select(condition, &left, &right)
                .bytes()
                .iter()
                .map(|v| value(v).expect("constant"))
                .collect::<Vec<_>>(),
            fields(&selected).to_vec()
        );
        assert_eq!(
            native(&Selected {
                condition,
                if_true: Bytes(left),
                if_false: Bytes(right),
                selected: fields(&selected)
            }),
            Ok(())
        );
        if N > 0 {
            let mut wrong = fields(&selected);
            let first = wrong.first_mut().expect("nonempty");
            *first = circuit::Field::from(ark_bn254::Fr::from(*first) + ark_bn254::Fr::from(1u64));
            assert_eq!(
                native(&Selected {
                    condition,
                    if_true: Bytes(left),
                    if_false: Bytes(right),
                    selected: wrong
                }),
                Err(SELECT_BROKEN)
            );
        }
    }
}

#[test]
fn byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries() {
    check::<0>([], []);
    check([0], [255]);
    check([255], [255]);
    check([0; 31], [255; 31]);
    check([255; 31], [255; 31]);
    check([0; 32], [0; 32]);
    for changed in [0, 30, 31] {
        let mut right = [0; 32];
        *right.get_mut(changed).expect("byte") = 1;
        check([0; 32], right);
    }
    let mut right = [0; 63];
    *right.last_mut().expect("byte") = 1;
    check([0; 63], right);
}

#[test]
fn empty_arrays_are_equal_and_cannot_satisfy_not_equal() {
    let empty = circuit::Bytes::<0>::constant(&[]);
    empty
        .is_equal(&empty)
        .expect("empty equality")
        .assert_true("empty arrays equal")
        .expect("true");
    assert_eq!(
        native(&AssertNotEqual::<0> {
            left: Bytes([]),
            right: Bytes([])
        }),
        Err(NOT_EQUAL_BROKEN)
    );
}
