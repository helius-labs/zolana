use super::fixtures::*;
use crate::{
    bytes::support::{byte_rows, fields, golden, low_bits},
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, check_constraints, check_private_variables, check_tampered, exported, size,
            with_wires,
        },
    },
};
use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::Field, Bytes, ZkCircuit};

fn complete<F: ZkCircuit>(fixture: &F) {
    let r1cs = exported::<F>();
    assert_eq!(check_constraints(fixture), Ok(r1cs.header.constraints));
    assert_eq!(r1cs.first_unsatisfied(&assignment(fixture)), None);
    let report = check_private_variables(fixture);
    assert!(report.free.is_empty(), "{report:?}");
    assert!(report.tolerated.iter().all(|v| v
        .allocation
        .as_ref()
        .is_some_and(|label| label.text == "the inverse hint of an equality test")));
}

#[test]
fn one_byte_equality_has_range_checks_then_one_equality_row() {
    let one = Fr::one();
    assert_eq!(
        exported::<AssertEqual<1>>(),
        golden(
            19,
            [
                byte_rows(1),
                byte_rows(10),
                vec![(vec![(one, 1), (-one, 10)], vec![(one, 0)], vec![])]
            ]
            .concat()
        )
    );
}

fn across_width<const N: usize>() {
    let left = Bytes([3; N]);
    let right = Bytes([7; N]);
    complete(&AssertEqual { left, right: left });
    for condition in [false, true] {
        complete(&AssertEqualIf {
            left,
            right: if condition { left } else { right },
            condition,
        });
        complete(&IsEqual {
            left,
            right: if condition { left } else { right },
            claimed: condition || N == 0,
        });
        complete(&Selected {
            condition,
            if_true: left,
            if_false: right,
            selected: fields(if condition { &left.0 } else { &right.0 }),
        });
    }
    if N > 0 {
        complete(&AssertNotEqual { left, right });
    }
}

#[test]
fn honest_assertions_and_select_have_stable_shape_and_no_unexpected_free_variables() {
    across_width::<0>();
    across_width::<1>();
    across_width::<31>();
    across_width::<32>();
    across_width::<63>();
}

#[test]
fn changed_equality_operands_with_honest_range_bits_break_the_relation() {
    let fixture = AssertEqual {
        left: Bytes([3; 32]),
        right: Bytes([3; 32]),
    };
    let conditional = AssertEqualIf {
        left: fixture.left,
        right: fixture.right,
        condition: true,
    };
    for index in [0, 30, 31] {
        let wire = 1 + 9 * 32 + 9 * index;
        let changes: Vec<_> = std::iter::once((wire, Fr::from(4u64)))
            .chain((wire + 1..).zip(low_bits(4)))
            .collect();
        assert_eq!(
            exported::<AssertEqual<32>>()
                .first_unsatisfied(&with_wires(assignment(&fixture), &changes)),
            Some(576 + index / 31)
        );
        assert!(exported::<AssertEqualIf<32>>()
            .first_unsatisfied(&with_wires(assignment(&conditional), &changes))
            .is_some());
        let disabled = AssertEqualIf {
            condition: false,
            ..conditional
        };
        assert_eq!(
            exported::<AssertEqualIf<32>>()
                .first_unsatisfied(&with_wires(assignment(&disabled), &changes)),
            None
        );
    }
}

#[test]
fn every_selected_byte_and_the_equality_claim_are_constrained() {
    for condition in [false, true] {
        let fixture = Selected {
            condition,
            if_true: Bytes([3; 32]),
            if_false: Bytes([7; 32]),
            selected: [Field::from(if condition { 3u64 } else { 7u64 }); 32],
        };
        for index in 0..32 {
            let wire = 2 + 18 * 32 + index;
            assert!(check_tampered(&fixture, wire, Field::from(8u64)).is_err());
            assert!(exported::<Selected<32>>()
                .first_unsatisfied(&with_wires(assignment(&fixture), &[(wire, Fr::from(8u64))]))
                .is_some());
        }
        let equality = IsEqual {
            left: Bytes([3; 32]),
            right: Bytes([if condition { 3 } else { 7 }; 32]),
            claimed: condition,
        };
        assert!(check_tampered(&equality, 577, Field::from(!condition)).is_err());
    }
}

#[test]
fn operation_counts_and_digests_are_pinned() {
    let observed = [
        (size::<AssertEqual<32>>(), r1cs_digest::<AssertEqual<32>>()),
        (
            size::<AssertEqualIf<32>>(),
            r1cs_digest::<AssertEqualIf<32>>(),
        ),
        (
            size::<AssertNotEqual<32>>(),
            r1cs_digest::<AssertNotEqual<32>>(),
        ),
        (size::<IsEqual<32>>(), r1cs_digest::<IsEqual<32>>()),
        (size::<Selected<32>>(), r1cs_digest::<Selected<32>>()),
    ];
    let expected = [
        (
            578,
            577,
            "3b71c49120f143a16bd97686fd92e2a6942fedae2795ea6cb57bb68ebfe95bf5",
        ),
        (
            579,
            578,
            "fc4c662d03e0e6a84a0eff6bcabc813a007bc59d512b37014999de0722b4d2e0",
        ),
        (
            583,
            583,
            "bc4ee082b003ee2896f012fc407e2d7faabb24d1e8e1ee2e74b8ddd50f04dc2b",
        ),
        (
            584,
            584,
            "2bb5bc6479dba6eefad44d9e8f88ae52d031c2ae8c4cdc1cf99a83b45e6611a2",
        ),
        (
            641,
            642,
            "a4bf3eee0b2c50c3f841b860bac22957fe6304c4246378376277a07652199304",
        ),
    ]
    .map(|(constraints, variables, digest)| {
        (
            crate::harness::fixture::Size {
                constraints,
                variables,
            },
            digest.to_owned(),
        )
    });
    assert_eq!(observed, expected);
}

#[test]
fn constant_assertions_and_selection_add_no_constraint_or_variable() {
    assert_eq!(exported::<ConstantOps>(), golden(1, vec![]));
    assert_eq!(check_constraints(&ConstantOps), Ok(0));
}

#[test]
fn making_inequality_operands_equal_with_valid_byte_bits_is_unsatisfied() {
    let fixture = AssertNotEqual {
        left: Bytes([3; 32]),
        right: Bytes([7; 32]),
    };
    let wires: Vec<_> = (0..32)
        .flat_map(|index| {
            let wire = 289 + 9 * index;
            std::iter::once((wire, Fr::from(3u64))).chain((wire + 1..).zip(low_bits(3)))
        })
        .collect();
    assert!(exported::<AssertNotEqual<32>>()
        .first_unsatisfied(&with_wires(assignment(&fixture), &wires))
        .is_some());
}
