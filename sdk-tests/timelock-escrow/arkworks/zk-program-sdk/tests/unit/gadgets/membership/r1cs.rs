use super::{
    fixtures::{is_in_fixture, AssertIn, InConstants, IsIn, FLAG_RULE},
    vectors::VECTORS,
};
use crate::harness::{
    field::field,
    fixture::{
        assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
        exported, size, with_wires, Size,
    },
    iden3::{R1cs, R1csHeader},
};
use ark_bn254::Fr;
use zk_program_sdk::{
    circuit::{Field, VariableRole},
    ZkCircuit,
};

#[test]
fn assertion_exports_exactly_the_distance_product_and_zero_row() {
    let one = Fr::from(1u64);
    assert_eq!(
        exported::<AssertIn<3>>(),
        R1cs {
            header: R1csHeader::bn254(7, 0, 6, 3),
            a: vec![vec![(one, 1), (-one, 2)], vec![(one, 5)], vec![(-one, 6)]],
            b: vec![
                vec![(one, 1), (-one, 3)],
                vec![(one, 1), (-one, 4)],
                vec![(one, 0)]
            ],
            c: vec![vec![(one, 5)], vec![(one, 6)], vec![]],
            wire_labels: (0..7).collect(),
        }
    );
}

#[test]
fn membership_exports_exactly_the_distance_product_zero_test_and_claim() {
    let one = Fr::from(1u64);
    assert_eq!(
        exported::<IsIn<3>>(),
        R1cs {
            header: R1csHeader::bn254(10, 0, 9, 5),
            a: vec![
                vec![(one, 1), (-one, 2)],
                vec![(one, 6)],
                vec![(-one, 7)],
                vec![(-one, 7)],
                vec![(one, 0), (-one, 5), (-one, 8)]
            ],
            b: vec![
                vec![(one, 1), (-one, 3)],
                vec![(one, 1), (-one, 4)],
                vec![(one, 9)],
                vec![(one, 0), (-one, 8)],
                vec![(one, 0)]
            ],
            c: vec![
                vec![(one, 6)],
                vec![(one, 7)],
                vec![(one, 8)],
                vec![],
                vec![]
            ],
            wire_labels: (0..10).collect(),
        }
    );
}

#[test]
fn constant_members_add_no_input_variables_and_empty_membership_is_false() {
    let one = Fr::from(1u64);
    assert_eq!(
        exported::<InConstants>(),
        R1cs {
            header: R1csHeader::bn254(3, 0, 2, 2),
            a: vec![vec![(-Fr::from(3u64), 0), (one, 1)], vec![(-one, 2)]],
            b: vec![vec![(-Fr::from(5u64), 0), (one, 1)], vec![(one, 0)]],
            c: vec![vec![(one, 2)], vec![]],
            wire_labels: (0..3).collect(),
        }
    );
    assert_eq!(
        check_constraints(&is_in_fixture::<0>(field("8"), [], false)),
        Ok(1)
    );
    assert_eq!(
        AssertIn::<0>::export_r1cs().unwrap_err().name(),
        "CircuitError.RuleBroken"
    );
}

#[test]
fn counts_grow_by_one_row_and_two_variables_per_member() {
    fn check<const N: usize>() {
        assert_eq!(
            size::<IsIn<N>>(),
            Size {
                constraints: N + 2,
                variables: 2 * N + 4
            }
        );
        assert_eq!(
            size::<AssertIn<N>>(),
            Size {
                constraints: N,
                variables: 2 * N + 1
            }
        );
    }
    check::<1>();
    check::<2>();
    check::<3>();
    check::<8>();
}

/// Recomputes all products for an outsider, isolating the assertion row.
pub fn outsider_witness(fixture: &AssertIn<3>) -> Vec<Fr> {
    let value = Fr::from(fixture.value);
    let [first, second, third] = fixture.set.map(Fr::from);
    let partial = (value - first) * (value - second);
    vec![
        Fr::from(1u64),
        value,
        first,
        second,
        third,
        partial,
        partial * (value - third),
    ]
}

#[test]
fn every_vector_checks_the_placeholder_and_refuses_a_wrong_or_nonboolean_flag() {
    for vector in VECTORS {
        let fixture = vector.is_in();
        assert_eq!(check_constraints(&fixture), Ok(5), "{}", vector.name);
        assert_eq!(
            exported::<IsIn<3>>().first_unsatisfied(&assignment(&fixture)),
            None
        );
        for claimed in [Field::from(!vector.member), field("2")] {
            assert_eq!(
                check_tampered(&fixture, 5, claimed),
                Err(breaks_rule(4, FLAG_RULE))
            );
        }
        if vector.member {
            assert_eq!(check_constraints(&vector.assert_in()), Ok(3));
            assert_eq!(
                exported::<AssertIn<3>>().first_unsatisfied(&assignment(&vector.assert_in())),
                None
            );
        } else {
            assert_eq!(
                exported::<AssertIn<3>>().first_unsatisfied(&outsider_witness(&vector.assert_in())),
                Some(2)
            );
            let honest = AssertIn {
                value: vector.set()[0],
                set: vector.set(),
            };
            let dishonest = with_wires(assignment(&honest), &[(1, vector.value().into())]);
            assert!(exported::<AssertIn<3>>()
                .first_unsatisfied(&dishonest)
                .is_some());
            assert!(check_tampered(&honest, 1, vector.value()).is_err());
        }
    }
}

#[test]
fn only_nonbinding_set_inputs_and_equality_inverse_hints_can_be_free() {
    let expected_free = [
        vec![1, 3],
        vec![2, 3],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![1, 2, 3],
        vec![],
        vec![],
    ];
    for (vector, expected) in VECTORS.iter().zip(expected_free) {
        let report = check_private_variables(&vector.is_in());
        assert_eq!((report.constraints, report.private_variables), (5, 9));
        assert_eq!(
            report
                .free
                .iter()
                .map(|free| free.variable)
                .collect::<Vec<_>>(),
            expected,
            "{}",
            vector.name
        );
        let tolerated: Vec<_> = report
            .tolerated
            .iter()
            .map(|free| {
                (
                    free.variable,
                    free.role,
                    free.allocation.as_ref().map(|allocation| allocation.text),
                )
            })
            .collect();
        assert_eq!(
            tolerated,
            if vector.member {
                vec![(
                    8,
                    VariableRole::Multiplier,
                    Some("the inverse hint of an equality test"),
                )]
            } else {
                vec![]
            }
        );
    }
}

#[test]
fn constant_membership_allocates_only_its_claim() {
    use super::fixtures::ConstantMembership;
    let one = Fr::from(1u64);
    assert_eq!(
        exported::<ConstantMembership>(),
        R1cs {
            header: R1csHeader::bn254(2, 0, 1, 1),
            a: vec![vec![(one, 0), (-one, 1)]],
            b: vec![vec![(one, 0)]],
            c: vec![vec![]],
            wire_labels: vec![0, 1],
        }
    );
    assert_eq!(
        check_constraints(&ConstantMembership { member: field("1") }),
        Ok(1)
    );
}
