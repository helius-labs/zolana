use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::Field, Bytes, ProverError, ZkCircuit};

use super::{
    fixtures::{
        allocated, pack_fixture, pack_forms, split_forms, Allocated, Computed, Constants, Pack,
        Split, FILE, PACK_FORMS, PACK_RULE, SPLIT_FORMS, SPLIT_RULE,
    },
    vectors::{Pair, Vector, TOO_LARGE, VALID, WIDE, WRONG},
};
use crate::{
    bytes::support::{
        boolean_row, byte_rows, golden, low_bits, recomposition_row, unsatisfied_rows, Rows,
        BYTE_RULE,
    },
    harness::{
        field::{field, MODULUS_MINUS_1},
        fixture::{
            assignment, breaks_rule, check_constraints, check_tampered, each, expected, exported,
            no_free_variable, per_vector, size, with_wires, Assignment, CheckConstraints, Export,
            Fixture, FreeVariables, ProverRefusal, Size, Visit,
        },
    },
};

fn size_of(constraints: usize, variables: usize) -> Size {
    Size {
        constraints,
        variables,
    }
}

/// The rows of `Split<N>`: the value's 8N boolean rows, the value row, then
/// one row per claimed byte, byte 0 on the most significant bits.
fn split_rows(n: usize) -> Rows {
    let (value, first_claim, first_bit) = (1, 2, 2 + n);
    let claims =
        (0..n).map(|byte| recomposition_row(first_claim + byte, first_bit + 8 * (n - 1 - byte), 8));
    (first_bit..first_bit + 8 * n)
        .map(boolean_row)
        .chain([recomposition_row(value, first_bit, 8 * n)])
        .chain(claims)
        .collect()
}

struct ExportedRows;

impl Visit<Computed> for ExportedRows {
    type Output = (Option<usize>, Result<usize, ProverRefusal>);

    fn visit<F: Fixture<Computed>>(&self, fixture: &F) -> Self::Output {
        (
            exported::<F>().first_unsatisfied(&assignment(fixture)),
            check_constraints(fixture),
        )
    }
}

/// The exported rows and the proving rows with one wire tampered.
struct TamperedWire(usize, Fr);

impl Visit<Computed> for TamperedWire {
    type Output = (Option<usize>, Result<(), ProverRefusal>);

    fn visit<F: Fixture<Computed>>(&self, fixture: &F) -> Self::Output {
        let TamperedWire(wire, value) = *self;
        (
            exported::<F>().first_unsatisfied(&with_wires(assignment(fixture), &[(wire, value)])),
            check_tampered(fixture, wire, Field::from(value)),
        )
    }
}

/// The exported rows with the claimed bytes, wires 2 to N + 1, overwritten.
struct ClaimedBytes(Vec<u8>);

impl Visit<Computed> for ClaimedBytes {
    type Output = Option<usize>;

    fn visit<F: Fixture<Computed>>(&self, fixture: &F) -> Option<usize> {
        let wires: Vec<(usize, Fr)> = self
            .0
            .iter()
            .enumerate()
            .map(|(byte, value)| (2 + byte, Fr::from(u64::from(*value))))
            .collect();
        exported::<F>().first_unsatisfied(&with_wires(assignment(fixture), &wires))
    }
}

fn every_fitting_vector() -> Vec<Vector> {
    [&VALID[..], &WIDE].concat()
}

#[test]
fn a_byte_proof_input_exports_exactly_eight_boolean_rows_and_one_recomposition_row() {
    assert_eq!(
        (exported::<Allocated<1>>(), exported::<Allocated<2>>()),
        (
            golden(10, byte_rows(1)),
            golden(19, [byte_rows(1), byte_rows(10)].concat())
        )
    );
}

#[test]
fn every_byte_proof_input_costs_exactly_nine_constraints_and_nine_variables() {
    assert_eq!(
        [
            size::<Allocated<0>>(),
            size::<Allocated<1>>(),
            size::<Allocated<2>>(),
            size::<Allocated<31>>(),
            size::<Allocated<32>>(),
        ],
        [0, 1, 2, 31, 32].map(|n| size_of(9 * n, 9 * n + 1))
    );
}

#[test]
fn every_valid_byte_proof_input_satisfies_every_row() {
    let vectors = every_fitting_vector();
    assert_eq!(
        per_vector(&vectors, |vector| allocated(&ExportedRows, &vector.pair())),
        per_vector(&vectors, |vector| (None, Ok(9 * vector.width())))
    );
}

#[test]
fn a_byte_witness_of_256_or_more_leaves_a_row_of_its_range_check_unsatisfied() {
    let r1cs = exported::<Allocated<1>>();
    let honest = assignment(&Allocated::<1> { bytes: Bytes([0]) });
    let with_byte = |byte: Fr, bits: [Fr; 8]| {
        let wires: Vec<(usize, Fr)> = std::iter::once((1, byte)).chain((2..).zip(bits)).collect();
        unsatisfied_rows(&r1cs, &with_wires(honest.clone(), &wires))
    };
    let with_bit = |bit: usize, value: Fr| {
        let mut bits = low_bits(0);
        *bits.get_mut(bit).expect("bit index") = value;
        bits
    };
    let p_minus_1: Fr = field(MODULUS_MINUS_1).into();
    assert_eq!(
        [
            with_byte(Fr::from(255u64), low_bits(255)),
            with_byte(Fr::from(256u64), low_bits(0)),
            with_byte(Fr::from(256u64), with_bit(7, Fr::from(2u64))),
            with_byte(p_minus_1, low_bits(0)),
            with_byte(p_minus_1, with_bit(0, -Fr::one())),
        ],
        [vec![], vec![8], vec![7], vec![8], vec![0]]
    );
}

#[test]
fn a_tampered_byte_or_bit_breaks_the_byte_proof_input_rule() {
    let fixture = Allocated::<2> {
        bytes: Bytes([5, 7]),
    };
    let tamper = |wire, value: u64| check_tampered(&fixture, wire, Field::from(value));
    assert_eq!(
        [
            tamper(1, 5),
            tamper(1, 256),
            tamper(10, 7 + 256),
            tamper(2, 2),
            tamper(11, 0),
        ],
        [
            Ok(()),
            Err(breaks_rule(8, BYTE_RULE)),
            Err(breaks_rule(17, BYTE_RULE)),
            Err(breaks_rule(0, BYTE_RULE)),
            Err(breaks_rule(17, BYTE_RULE)),
        ]
    );
}

#[test]
fn no_byte_or_bit_of_a_byte_proof_input_is_free() {
    let vectors = every_fitting_vector();
    assert_eq!(
        per_vector(&vectors, |vector| allocated(&FreeVariables, &vector.pair())),
        per_vector(&vectors, |vector| no_free_variable(
            9 * vector.width(),
            9 * vector.width()
        ))
    );
}

#[test]
fn constant_bytes_add_no_constraint_and_no_variable() {
    assert_eq!(
        (exported::<Constants>(), check_constraints(&Constants)),
        (golden(1, vec![]), Ok(0))
    );
}

#[test]
fn a_split_exports_its_bits_then_the_value_row_then_one_row_per_byte_most_significant_first() {
    assert_eq!(
        (
            exported::<Split<0, 0>>(),
            exported::<Split<1, 0>>(),
            exported::<Split<2, 0>>(),
        ),
        (
            golden(2, split_rows(0)),
            golden(11, split_rows(1)),
            golden(20, split_rows(2)),
        )
    );
}

#[test]
fn a_split_into_n_bytes_costs_exactly_9n_plus_1_constraints() {
    assert_eq!(
        [
            size::<Split<0, 0>>(),
            size::<Split<1, 0>>(),
            size::<Split<2, 0>>(),
            size::<Split<31, 0>>(),
        ],
        [0, 1, 2, 31].map(|n| size_of(9 * n + 1, 9 * n + 2))
    );
}

#[test]
fn both_split_forms_and_both_pack_forms_export_byte_identical_r1cs() {
    let exports = |forms: Vec<(&'static str, Vec<u8>)>| {
        let first = forms.first().expect("operand form").1.clone();
        (forms, first)
    };
    let (split, pack): (Vec<_>, Vec<_>) = VALID
        .iter()
        .map(|vector| {
            (
                exports(split_forms(&Export, &vector.pair())),
                exports(pack_forms(&Export, &vector.pair())),
            )
        })
        .unzip();
    assert_eq!(
        (
            split
                .iter()
                .map(|(forms, _)| forms.clone())
                .collect::<Vec<_>>(),
            pack.iter()
                .map(|(forms, _)| forms.clone())
                .collect::<Vec<_>>(),
        ),
        (
            split
                .iter()
                .map(|(_, first)| each(&SPLIT_FORMS, first.clone()))
                .collect::<Vec<_>>(),
            pack.iter()
                .map(|(_, first)| each(&PACK_FORMS, first.clone()))
                .collect::<Vec<_>>(),
        )
    );
}

#[test]
fn a_32_byte_split_or_pack_fails_to_export_with_bit_width_too_large() {
    let refusal = |result: Result<Vec<u8>, ProverError>| {
        result
            .map(|_| ())
            .map_err(|error| (error.name(), error.to_string(), error.location().file()))
    };
    let too_wide = Err((
        "CircuitError.BitWidthTooLarge",
        "a check over 256 bits is too wide; a circuit value holds at most 253 bits".to_string(),
        FILE,
    ));
    assert_eq!(
        [
            refusal(Split::<32, 0>::export_r1cs()),
            refusal(Split::<32, 1>::export_r1cs()),
            refusal(Pack::<32, 0>::export_r1cs()),
            refusal(Pack::<32, 1>::export_r1cs()),
        ],
        [
            too_wide.clone(),
            too_wide.clone(),
            too_wide.clone(),
            too_wide
        ]
    );
}

#[test]
fn every_valid_split_and_pack_satisfies_every_row() {
    assert_eq!(
        (
            per_vector(&VALID, |vector| split_forms(&ExportedRows, &vector.pair())),
            per_vector(&VALID, |vector| pack_forms(&ExportedRows, &vector.pair())),
        ),
        (
            expected(&VALID, &SPLIT_FORMS, |vector, _| (
                None,
                Ok(9 * vector.width() + 1)
            )),
            expected(&VALID, &PACK_FORMS, |vector, _| (
                None,
                Ok(9 * vector.width() + 1)
            )),
        )
    );
}

#[test]
fn the_split_assignment_is_the_value_the_claimed_bytes_then_the_value_bits() {
    let bits = (0..16).map(|bit| Fr::from((258u64 >> bit) & 1));
    assert_eq!(
        split_forms(&Assignment, &VALID[6].pair()),
        each(
            &SPLIT_FORMS,
            [Fr::one(), Fr::from(258u64), Fr::one(), Fr::from(2u64)]
                .into_iter()
                .chain(bits)
                .collect::<Vec<_>>()
        )
    );
}

#[test]
fn every_wrong_split_claim_leaves_its_first_wrong_byte_row_unsatisfied() {
    let first_wrong_row = |vector: &Vector| {
        let honest = vector.split_pair().bytes;
        let wrong = honest
            .iter()
            .zip(vector.bytes())
            .position(|(honest, claimed)| *honest != claimed)
            .expect("a wrong byte");
        Some(8 * vector.width() + 1 + wrong)
    };
    assert_eq!(
        per_vector(&WRONG, |vector| split_forms(
            &ClaimedBytes(vector.bytes()),
            &vector.split_pair()
        )),
        expected(&WRONG, &SPLIT_FORMS, |vector, _| first_wrong_row(vector))
    );
}

#[test]
fn a_value_too_large_for_its_bytes_leaves_the_unlabelled_value_row_unsatisfied() {
    assert_eq!(
        per_vector(&TOO_LARGE, |vector| split_forms(
            &TamperedWire(1, vector.value().into()),
            &vector.packed_pair()
        )),
        expected(&TOO_LARGE, &SPLIT_FORMS, |vector, _| {
            let row = 8 * vector.width();
            (
                Some(row),
                Err(("ProverError.ProofInputsBreakRule", Some(row), None)),
            )
        })
    );
}

#[test]
fn a_tampered_split_claim_breaks_the_split_rule() {
    assert_eq!(
        split_forms(&TamperedWire(2, Fr::from(2u64)), &VALID[6].pair()),
        each(&SPLIT_FORMS, (Some(17), Err(breaks_rule(17, SPLIT_RULE))))
    );
}

#[test]
fn every_valid_split_checks_its_constraints_in_both_forms() {
    assert_eq!(
        per_vector(&VALID, |vector| split_forms(
            &CheckConstraints,
            &vector.pair()
        )),
        expected(&VALID, &SPLIT_FORMS, |vector, _| Ok(9 * vector.width() + 1))
    );
}

#[test]
fn no_private_variable_of_a_split_or_pack_is_free() {
    let report =
        |vector: &Vector, _| no_free_variable(9 * vector.width() + 1, 9 * vector.width() + 1);
    assert_eq!(
        (
            per_vector(&VALID, |vector| split_forms(&FreeVariables, &vector.pair())),
            per_vector(&VALID, |vector| pack_forms(&FreeVariables, &vector.pair())),
        ),
        (
            expected(&VALID, &SPLIT_FORMS, report),
            expected(&VALID, &PACK_FORMS, report),
        )
    );
}

#[test]
fn a_pack_exports_the_byte_range_checks_then_exactly_one_packed_row() {
    let one = Fr::one();
    let packed_row = (
        vec![(Fr::from(256u64), 1), (one, 10), (-one, 19)],
        vec![(one, 0)],
        vec![],
    );
    assert_eq!(
        (
            exported::<Pack<0, 0>>(),
            exported::<Pack<1, 0>>(),
            exported::<Pack<2, 0>>(),
        ),
        (
            golden(2, vec![recomposition_row(1, 2, 0)]),
            golden(
                11,
                [
                    byte_rows(1),
                    vec![(vec![(one, 1), (-one, 10)], vec![(one, 0)], vec![])]
                ]
                .concat()
            ),
            golden(20, [byte_rows(1), byte_rows(10), vec![packed_row]].concat()),
        )
    );
}

#[test]
fn packing_adds_no_constraint_and_no_variable_beyond_the_byte_checks() {
    assert_eq!(
        [
            size::<Pack<0, 0>>(),
            size::<Pack<1, 0>>(),
            size::<Pack<2, 0>>(),
            size::<Pack<31, 0>>(),
        ],
        [0, 1, 2, 31].map(|n| size_of(9 * n + 1, 9 * n + 2))
    );
}

#[test]
fn every_wrong_packed_claim_leaves_exactly_the_packed_row_unsatisfied() {
    let wrong = [&WRONG[..], &TOO_LARGE].concat();
    assert_eq!(
        per_vector(&wrong, |vector| pack_forms(
            &TamperedWire(9 * vector.width() + 1, vector.value().into()),
            &vector.packed_pair()
        )),
        expected(&wrong, &PACK_FORMS, |vector, _| {
            let row = 9 * vector.width();
            (Some(row), Err(breaks_rule(row, PACK_RULE)))
        })
    );
}

#[test]
fn only_the_byte_range_checks_refuse_bytes_that_pack_to_the_same_value() {
    let honest = Pair {
        value: field("258"),
        bytes: vec![1, 2],
    };
    let fixture = pack_fixture::<2, 0>(&honest);
    let aliased = with_wires(
        assignment(&fixture),
        &[
            (1, Fr::from(0u64)),
            (2, Fr::from(0u64)),
            (10, Fr::from(258u64)),
        ],
    );
    assert_eq!(
        (
            unsatisfied_rows(&exported::<Pack<2, 0>>(), &aliased),
            check_tampered(&fixture, 10, Field::from(258u64)),
        ),
        (vec![17], Err(breaks_rule(17, BYTE_RULE)))
    );
}

#[test]
fn every_supported_byte_width_round_trips_with_the_same_setup_and_proving_shape() {
    fn check<const N: usize>() {
        let bytes: [u8; N] = std::array::from_fn(|i| (i as u8).wrapping_mul(11));
        let pair = Pair {
            value: crate::bytes::support::packed(&bytes),
            bytes: bytes.to_vec(),
        };
        let pack = pack_fixture::<N, 0>(&pair);
        let split = super::fixtures::split_fixture::<N, 0>(&pair);
        assert_eq!(crate::harness::fixture::native(&pack), Ok(()));
        assert_eq!(crate::harness::fixture::native(&split), Ok(()));
        assert_eq!(check_constraints(&pack), Ok(9 * N + 1));
        assert_eq!(check_constraints(&split), Ok(9 * N + 1));
        assert_eq!(
            exported::<Pack<N, 0>>().first_unsatisfied(&assignment(&pack)),
            None
        );
        assert_eq!(
            exported::<Split<N, 0>>().first_unsatisfied(&assignment(&split)),
            None
        );
    }
    macro_rules! widths { ($($n:literal),*) => { $(check::<$n>();)* }; }
    widths!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    );
}
