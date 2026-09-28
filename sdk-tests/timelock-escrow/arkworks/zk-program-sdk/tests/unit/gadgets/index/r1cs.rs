use super::{
    fixtures::{decoded, selected, OneHot, SelectIndex, FLAG_RULE, SELECT_RULE},
    vectors::{invalid_indices, items},
};
use crate::harness::{
    digest::r1cs_digest,
    field::field,
    fixture::{
        assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
        exported, size, with_wires, Size,
    },
    iden3::{R1cs, R1csHeader},
};
use ark_bn254::Fr;
use ark_ff::Field as ArkField;
use zk_program_sdk::{circuit::VariableRole, ZkCircuit};

#[test]
fn singleton_decode_exports_the_zero_test_bound_and_claim_rows() {
    let one = Fr::from(1u64);
    assert_eq!(
        exported::<OneHot<1>>(),
        R1cs {
            header: R1csHeader::bn254(5, 0, 4, 4),
            a: vec![
                vec![(-one, 1)],
                vec![(-one, 1)],
                vec![(one, 3)],
                vec![(one, 0), (-one, 2), (-one, 3)]
            ],
            b: vec![
                vec![(one, 4)],
                vec![(one, 0), (-one, 3)],
                vec![(one, 0)],
                vec![(one, 0)]
            ],
            c: vec![vec![(one, 3)], vec![], vec![], vec![]],
            wire_labels: (0..5).collect(),
        }
    );
}

#[test]
fn singleton_selection_exports_no_selection_witness() {
    let one = Fr::from(1u64);
    assert_eq!(
        exported::<SelectIndex<1>>(),
        R1cs {
            header: R1csHeader::bn254(6, 0, 5, 4),
            a: vec![
                vec![(-one, 2)],
                vec![(-one, 2)],
                vec![(one, 4)],
                vec![(one, 1), (-one, 3)]
            ],
            b: vec![
                vec![(one, 5)],
                vec![(one, 0), (-one, 4)],
                vec![(one, 0)],
                vec![(one, 0)]
            ],
            c: vec![vec![(one, 4)], vec![], vec![], vec![]],
            wire_labels: (0..6).collect(),
        }
    );
}

#[test]
fn indexing_sizes_and_three_item_digests_are_pinned() {
    fn check<const N: usize>() {
        assert_eq!(
            size::<OneHot<N>>(),
            Size {
                constraints: 3 * N + 1,
                variables: 3 * N + 2
            }
        );
        assert_eq!(
            size::<SelectIndex<N>>(),
            Size {
                constraints: 3 * N + 1,
                variables: 4 * N + 2
            }
        );
    }
    check::<1>();
    check::<3>();
    check::<8>();
    assert_eq!(
        r1cs_digest::<OneHot<3>>(),
        "efac921fe11299776b46156021a69a29dad6487cfcaf1050a2431d78f782907e"
    );
    assert_eq!(
        r1cs_digest::<SelectIndex<3>>(),
        "6fa3c03eabf883fe56e081d2b8537278f07ad963b25955d9d78d112af7ae618a"
    );
}

#[test]
fn all_valid_indices_check_the_placeholder_and_bind_each_flag_and_selection() {
    for index in 0..3 {
        let flags = decoded::<3>(index);
        assert_eq!(check_constraints(&flags), Ok(10));
        assert_eq!(
            exported::<OneHot<3>>().first_unsatisfied(&assignment(&flags)),
            None
        );
        for (position, flag) in flags.flags.iter().enumerate() {
            assert_eq!(
                check_tampered(&flags, position + 2, *flag + field("1")),
                Err(breaks_rule(7 + position, FLAG_RULE))
            );
        }
        for items in items() {
            let fixture = selected(items, index);
            assert_eq!(check_constraints(&fixture), Ok(10));
            assert_eq!(
                exported::<SelectIndex<3>>().first_unsatisfied(&assignment(&fixture)),
                None
            );
            assert_eq!(
                check_tampered(&fixture, 5, fixture.selected + field("1")),
                Err(breaks_rule(9, SELECT_RULE))
            );
        }
    }
}

/// A complete dishonest witness: all equality tests and output claims hold,
/// so only the in-bounds sum can reject an index outside 0..3.
pub fn out_of_bounds_one_hot(index: zk_program_sdk::circuit::Field) -> Vec<Fr> {
    let mut witness = assignment(&decoded::<3>(0));
    *witness.get_mut(1).expect("index") = index.into();
    for position in 0..3 {
        *witness.get_mut(position + 2).expect("flag") = Fr::from(0u64);
        *witness.get_mut(5 + 2 * position).expect("not equal") = Fr::from(1u64);
        *witness.get_mut(6 + 2 * position).expect("inverse") = (Fr::from(position as u64)
            - Fr::from(index))
        .inverse()
        .expect("out of bounds");
    }
    witness
}

pub fn out_of_bounds_selection(index: zk_program_sdk::circuit::Field) -> Vec<Fr> {
    let mut witness = assignment(&selected([field("7"); 3], 0));
    *witness.get_mut(4).expect("index") = index.into();
    for position in 0..3 {
        *witness.get_mut(6 + 2 * position).expect("not equal") = Fr::from(1u64);
        *witness.get_mut(7 + 2 * position).expect("inverse") = (Fr::from(position as u64)
            - Fr::from(index))
        .inverse()
        .expect("out of bounds");
    }
    witness
}

#[test]
fn out_of_bounds_indices_cannot_satisfy_the_exported_or_proving_rows() {
    let flags = decoded::<3>(0);
    let selection = selected([field("7"); 3], 0);
    for index in invalid_indices() {
        assert_eq!(
            exported::<OneHot<3>>().first_unsatisfied(&out_of_bounds_one_hot(index)),
            Some(6)
        );
        assert_eq!(
            exported::<SelectIndex<3>>().first_unsatisfied(&out_of_bounds_selection(index)),
            Some(6)
        );
        assert!(exported::<OneHot<3>>()
            .first_unsatisfied(&with_wires(assignment(&flags), &[(1, index.into())]))
            .is_some());
        assert!(check_tampered(&flags, 1, index).is_err());
        assert!(exported::<SelectIndex<3>>()
            .first_unsatisfied(&with_wires(assignment(&selection), &[(4, index.into())]))
            .is_some());
        assert!(check_tampered(&selection, 4, index).is_err());
    }
    assert_eq!(
        OneHot::<0>::export_r1cs().unwrap_err().name(),
        "CircuitError.IndexOutOfBounds"
    );
    assert_eq!(
        SelectIndex::<0>::export_r1cs().unwrap_err().name(),
        "CircuitError.IndexOutOfBounds"
    );
}

#[test]
fn decoder_flags_are_bound_and_only_the_matching_inverse_hint_is_tolerated() {
    for index in 0..3 {
        let report = check_private_variables(&decoded::<3>(index));
        assert_eq!(
            (report.constraints, report.private_variables, report.free),
            (10, 10, vec![])
        );
        assert_eq!(
            report
                .tolerated
                .iter()
                .map(|free| (free.variable, free.role))
                .collect::<Vec<_>>(),
            vec![(5 + 2 * index, VariableRole::Multiplier)]
        );
    }
}

#[test]
fn selection_reports_unused_inputs_without_claiming_joint_uniqueness() {
    for index in 0..3 {
        let report =
            check_private_variables(&selected([field("3"), field("5"), field("7")], index));
        assert_eq!(
            report
                .free
                .iter()
                .map(|free| free.variable)
                .collect::<Vec<_>>(),
            [vec![1, 2], vec![2], vec![1]]
                .get(index)
                .expect("index")
                .clone()
        );
        assert_eq!(
            report
                .tolerated
                .iter()
                .map(|free| (free.variable, free.role))
                .collect::<Vec<_>>(),
            vec![(6 + 2 * index, VariableRole::Multiplier)]
        );
    }
}

#[test]
fn constant_indexing_adds_no_rows_or_witnesses_before_the_claims() {
    use super::fixtures::ConstantIndex;
    let one = Fr::from(1u64);
    assert_eq!(
        exported::<ConstantIndex>(),
        R1cs {
            header: R1csHeader::bn254(5, 0, 4, 4),
            a: vec![
                vec![(-one, 1)],
                vec![(one, 0), (-one, 2)],
                vec![(-one, 3)],
                vec![(Fr::from(5u64), 0), (-one, 4)]
            ],
            b: vec![vec![(one, 0)]; 4],
            c: vec![vec![]; 4],
            wire_labels: (0..5).collect(),
        }
    );
    assert_eq!(
        check_constraints(&ConstantIndex {
            flags: [field("0"), field("1"), field("0")],
            selected: field("5")
        }),
        Ok(4)
    );
}
