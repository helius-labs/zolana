use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{circuit::Field, testing::PrivateVariableReport};

use super::{
    fixtures::{
        gadget_wire, result, witness, Add, CheckedAdd, CheckedMul, CheckedSub, Mul, Op, Sum,
        ADD_RULE, CLAIMED_WIRE, FIRST_BIT, MUL_RULE, RULE, SUB_RULE, X_WIRE, Y_WIRE,
    },
    vectors::edges,
};
use crate::{
    harness::{
        digest::r1cs_digest,
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            export, exported, first_unsatisfied, no_free_variable, size, Fixture, ProverRefusal,
            Size, Visit,
        },
        iden3::R1csHeader,
    },
    uint::rows::{
        bit_pattern, decomposition, field, golden, linear, product, rows, with_bits, Rows,
    },
};

fn derived(op: Op, bits: u32) -> Rows {
    let one = Fr::one();
    let n = bits as usize;
    let (x, y, claimed) = ([(one, X_WIRE)], [(one, Y_WIRE)], (-one, CLAIMED_WIRE));
    let operands = [
        decomposition(&x, FIRST_BIT, n),
        decomposition(&y, FIRST_BIT + n, n),
    ];
    let gadget = gadget_wire(bits);
    let (sum, difference) = (
        [(one, X_WIRE), (one, Y_WIRE)],
        [(one, X_WIRE), (-one, Y_WIRE)],
    );
    let own = match op {
        Op::Add => vec![linear(&[sum[0], sum[1], claimed])],
        Op::Mul => vec![
            product(&x, &y, &[(one, gadget)]),
            linear(&[(one, gadget), claimed]),
        ],
        Op::CheckedAdd => [
            decomposition(&sum, gadget, n),
            vec![linear(&[sum[0], sum[1], claimed])],
        ]
        .concat(),
        Op::CheckedMul => [
            vec![product(&x, &y, &[(one, gadget)])],
            decomposition(&[(one, gadget)], gadget + 1, n),
            vec![linear(&[(one, gadget), claimed])],
        ]
        .concat(),
        Op::CheckedSub => [
            decomposition(&difference, gadget, n),
            vec![linear(&[difference[0], difference[1], claimed])],
        ]
        .concat(),
    };
    golden(operands.into_iter().chain([own]))
}

#[test]
fn every_4_bit_operation_exports_exactly_its_golden_rows_and_header() {
    let header =
        |variables, constraints| R1csHeader::bn254(variables, 0, variables - 1, constraints);
    let one = Fr::one();
    let sum = golden([
        decomposition(&[(one, 1)], 5, 4),
        decomposition(&[(one, 2)], 9, 4),
        decomposition(&[(one, 3)], 13, 4),
        vec![linear(&[(one, 1), (one, 2), (one, 3), (-one, 4)])],
    ]);
    assert_eq!(
        [
            (
                exported::<Add<4, 5>>().header,
                rows(exported::<Add<4, 5>>())
            ),
            (
                exported::<Mul<4, 8>>().header,
                rows(exported::<Mul<4, 8>>())
            ),
            (
                exported::<Sum<4, 6>>().header,
                rows(exported::<Sum<4, 6>>())
            ),
            (
                exported::<CheckedAdd<4>>().header,
                rows(exported::<CheckedAdd<4>>())
            ),
            (
                exported::<CheckedMul<4>>().header,
                rows(exported::<CheckedMul<4>>())
            ),
            (
                exported::<CheckedSub<4>>().header,
                rows(exported::<CheckedSub<4>>())
            ),
        ],
        [
            (header(12, 11), derived(Op::Add, 4)),
            (header(13, 12), derived(Op::Mul, 4)),
            (header(17, 16), sum),
            (header(16, 16), derived(Op::CheckedAdd, 4)),
            (header(17, 17), derived(Op::CheckedMul, 4)),
            (header(16, 16), derived(Op::CheckedSub, 4)),
        ]
    );
}

#[test]
fn the_output_width_of_add_mul_and_sum_does_not_change_the_export() {
    assert_eq!(
        [
            export::<Add<4, 5>>() == export::<Add<4, 253>>(),
            export::<Mul<4, 8>>() == export::<Mul<4, 253>>(),
            export::<Sum<4, 6>>() == export::<Sum<4, 253>>(),
        ],
        [true, true, true]
    );
}

#[test]
fn every_operation_costs_its_counted_constraints_and_variables_at_64_126_and_252_bits() {
    let counted = |op: Op, bits: usize| {
        let (constraints, variables) = match op {
            Op::Add => (2 * (bits + 1) + 1, 4 + 2 * bits),
            Op::Mul => (2 * (bits + 1) + 2, 5 + 2 * bits),
            Op::CheckedAdd | Op::CheckedSub => (3 * (bits + 1) + 1, 4 + 3 * bits),
            Op::CheckedMul => (3 * (bits + 1) + 2, 5 + 3 * bits),
        };
        Size {
            constraints,
            variables,
        }
    };
    assert_eq!(
        [
            size::<Add<64, 65>>(),
            size::<Add<252, 253>>(),
            size::<Mul<64, 128>>(),
            size::<Mul<126, 252>>(),
            size::<CheckedAdd<64>>(),
            size::<CheckedAdd<252>>(),
            size::<CheckedMul<64>>(),
            size::<CheckedMul<126>>(),
            size::<CheckedSub<64>>(),
            size::<CheckedSub<252>>(),
        ],
        [
            counted(Op::Add, 64),
            counted(Op::Add, 252),
            counted(Op::Mul, 64),
            counted(Op::Mul, 126),
            counted(Op::CheckedAdd, 64),
            counted(Op::CheckedAdd, 252),
            counted(Op::CheckedMul, 64),
            counted(Op::CheckedMul, 126),
            counted(Op::CheckedSub, 64),
            counted(Op::CheckedSub, 252),
        ]
    );
}

#[test]
fn the_wide_checked_operations_export_the_derived_rows_and_pinned_digests() {
    assert_eq!(
        [
            (
                rows(exported::<CheckedAdd<64>>()),
                r1cs_digest::<CheckedAdd<64>>()
            ),
            (
                rows(exported::<CheckedAdd<252>>()),
                r1cs_digest::<CheckedAdd<252>>()
            ),
            (
                rows(exported::<CheckedMul<64>>()),
                r1cs_digest::<CheckedMul<64>>()
            ),
            (
                rows(exported::<CheckedMul<126>>()),
                r1cs_digest::<CheckedMul<126>>()
            ),
            (
                rows(exported::<CheckedSub<64>>()),
                r1cs_digest::<CheckedSub<64>>()
            ),
            (
                rows(exported::<CheckedSub<252>>()),
                r1cs_digest::<CheckedSub<252>>()
            ),
        ],
        [
            (
                derived(Op::CheckedAdd, 64),
                "3f5984ae62c2bcb7172677da44844e897e94d3ae9e51d5704f060523f05e25a6".to_string()
            ),
            (
                derived(Op::CheckedAdd, 252),
                "ce3d9c9820e169434167ad19909a2be488bff3b9ed6d5adf1535d65d3637a0a0".to_string()
            ),
            (
                derived(Op::CheckedMul, 64),
                "8e511921ad58ceab456c591438ea37ace4215be0312df0e02a2a78e287a55beb".to_string()
            ),
            (
                derived(Op::CheckedMul, 126),
                "6c189ba6fe001d275c4f3481a7fb893b9fe3ae7c2cb9027b58bc97513bf63ec7".to_string()
            ),
            (
                derived(Op::CheckedSub, 64),
                "9ef7411e660b28ac83b1a02b57e5c67469eb83318f4f225f862b8dfe56d8fb5c".to_string()
            ),
            (
                derived(Op::CheckedSub, 252),
                "acab11044ab44c3cb85a4fac8acd52dd98d57d6b24c8612b13fe2be0486d9f23".to_string()
            ),
        ]
    );
}

const OPS: [Op; 5] = [
    Op::Add,
    Op::Mul,
    Op::CheckedAdd,
    Op::CheckedMul,
    Op::CheckedSub,
];
const CHECKED: [Op; 3] = [Op::CheckedAdd, Op::CheckedMul, Op::CheckedSub];

fn pairs() -> impl Iterator<Item = (u64, u64)> {
    (0..16u64).flat_map(|x| (0..16u64).map(move |y| (x, y)))
}

fn fits(op: Op, x: u64, y: u64) -> bool {
    match op {
        Op::Add | Op::Mul => true,
        Op::CheckedAdd => x + y < 16,
        Op::CheckedMul => x * y < 16,
        Op::CheckedSub => x >= y,
    }
}

struct Honest;

impl Visit for Honest {
    type Output = (Result<usize, ProverRefusal>, Vec<Fr>, Option<usize>);

    fn visit<F: Fixture>(&self, fixture: &F) -> Self::Output {
        let witness = assignment(fixture);
        let unsatisfied = first_unsatisfied::<F>(&witness);
        (check_constraints(fixture), witness, unsatisfied)
    }
}

fn visit_4<V: Visit>(visitor: &V, op: Op, x: Fr, y: Fr, claimed: Fr) -> V::Output {
    let (x, y, claimed) = (field(x), field(y), field(claimed));
    match op {
        Op::Add => visitor.visit(&Add::<4, 5> { x, y, claimed }),
        Op::Mul => visitor.visit(&Mul::<4, 8> { x, y, claimed }),
        Op::CheckedAdd => visitor.visit(&CheckedAdd::<4> { x, y, claimed }),
        Op::CheckedMul => visitor.visit(&CheckedMul::<4> { x, y, claimed }),
        Op::CheckedSub => visitor.visit(&CheckedSub::<4> { x, y, claimed }),
    }
}

fn constraints(op: Op, bits: usize) -> usize {
    match op {
        Op::Add => 2 * (bits + 1) + 1,
        Op::Mul => 2 * (bits + 1) + 2,
        Op::CheckedAdd | Op::CheckedSub => 3 * (bits + 1) + 1,
        Op::CheckedMul => 3 * (bits + 1) + 2,
    }
}

#[test]
fn at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness() {
    let honest = |op: Op, x: u64, y: u64| {
        let (x, y) = (Fr::from(x), Fr::from(y));
        visit_4(&Honest, op, x, y, result(op, x, y))
    };
    let fitting = || {
        OPS.into_iter()
            .flat_map(|op| pairs().map(move |(x, y)| (op, x, y)))
            .filter(|(op, x, y)| fits(*op, *x, *y))
    };
    assert_eq!(
        fitting()
            .map(|(op, x, y)| honest(op, x, y))
            .collect::<Vec<_>>(),
        fitting()
            .map(|(op, x, y)| {
                let (x, y) = (Fr::from(x), Fr::from(y));
                (
                    Ok(constraints(op, 4)),
                    witness(op, 4, x, y, result(op, x, y)),
                    None,
                )
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_fitting_wide_edge_satisfies_every_row_with_the_derived_witness() {
    let fitting = || edges().into_iter().filter(|edge| edge.fits);
    assert_eq!(
        fitting()
            .map(|edge| (edge.name, edge.visit(&Honest)))
            .collect::<Vec<_>>(),
        fitting()
            .map(|edge| {
                let claimed = result(edge.op, edge.x, edge.y);
                let bits = edge.bits as usize;
                (
                    edge.name,
                    (
                        Ok(constraints(edge.op, bits)),
                        witness(edge.op, edge.bits, edge.x, edge.y, claimed),
                        None,
                    ),
                )
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn at_4_bits_add_and_mul_rows_hold_exactly_for_the_integer_result() {
    let r1cs = |op: Op| match op {
        Op::Add => exported::<Add<4, 5>>(),
        _ => exported::<Mul<4, 8>>(),
    };
    let satisfying = |op: Op| {
        let r1cs = r1cs(op);
        pairs()
            .flat_map(|(x, y)| (0..256u64).map(move |claimed| (x, y, claimed)))
            .filter(|(x, y, claimed)| {
                let witness = witness(op, 4, Fr::from(*x), Fr::from(*y), Fr::from(*claimed));
                r1cs.first_unsatisfied(&witness).is_none()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        (satisfying(Op::Add), satisfying(Op::Mul)),
        (
            pairs().map(|(x, y)| (x, y, x + y)).collect::<Vec<_>>(),
            pairs().map(|(x, y)| (x, y, x * y)).collect::<Vec<_>>()
        )
    );
}

#[test]
fn at_4_bits_only_the_digits_of_a_fitting_result_satisfy_a_checked_operation() {
    let satisfying = |op: Op| {
        let r1cs = match op {
            Op::CheckedAdd => exported::<CheckedAdd<4>>(),
            Op::CheckedMul => exported::<CheckedMul<4>>(),
            _ => exported::<CheckedSub<4>>(),
        };
        let first = gadget_wire(4) + usize::from(op == Op::CheckedMul);
        pairs()
            .flat_map(|(x, y)| (0..16u64).map(move |pattern| (x, y, pattern)))
            .filter(|(x, y, pattern)| {
                let (x, y) = (Fr::from(*x), Fr::from(*y));
                let honest = witness(op, 4, x, y, result(op, x, y));
                let witness = with_bits(honest, first, &bit_pattern(*pattern, 4));
                r1cs.first_unsatisfied(&witness).is_none()
            })
            .collect::<Vec<_>>()
    };
    let expected = |op: Op| {
        pairs()
            .filter(|(x, y)| fits(op, *x, *y))
            .map(|(x, y)| {
                let result = match op {
                    Op::CheckedAdd => x + y,
                    Op::CheckedMul => x * y,
                    _ => x - y,
                };
                (x, y, result)
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(CHECKED.map(satisfying), CHECKED.map(expected));
}

#[test]
fn a_wide_result_that_does_not_fit_leaves_exactly_the_range_check_sum_row_unsatisfied() {
    struct Unsatisfied(Vec<Fr>);
    impl Visit for Unsatisfied {
        type Output = Option<usize>;

        fn visit<F: Fixture>(&self, _fixture: &F) -> Option<usize> {
            first_unsatisfied::<F>(&self.0)
        }
    }
    let overflowing = || edges().into_iter().filter(|edge| !edge.fits);
    assert_eq!(
        overflowing()
            .map(|edge| {
                let claimed = result(edge.op, edge.x, edge.y);
                let witness = witness(edge.op, edge.bits, edge.x, edge.y, claimed);
                (edge.name, edge.visit(&Unsatisfied(witness)))
            })
            .collect::<Vec<_>>(),
        overflowing()
            .map(|edge| {
                let bits = edge.bits as usize;
                let sum_row = 3 * bits + 2 + usize::from(edge.op == Op::CheckedMul);
                (edge.name, Some(sum_row))
            })
            .collect::<Vec<_>>()
    );
}

fn tampered<F: Fixture>(fixture: &F, tampers: &[(usize, u64)]) -> Vec<Result<(), ProverRefusal>> {
    tampers
        .iter()
        .map(|(wire, value)| check_tampered(fixture, *wire, Field::from(*value)))
        .collect()
}

#[test]
fn the_proving_rows_name_the_operation_rule_for_tampered_digits_and_the_claim_rule_for_a_claim() {
    let fixture =
        |x: u64, y: u64, claimed: u64| (Field::from(x), Field::from(y), Field::from(claimed));
    let ((ax, ay, ac), (mx, my, mc), (sx, sy, sc)) =
        (fixture(7, 1, 8), fixture(3, 5, 15), fixture(9, 4, 5));
    let unlabelled = |row| Err(("ProverError.ProofInputsBreakRule", Some(row), None));
    assert_eq!(
        [
            tampered(
                &CheckedAdd::<4> {
                    x: ax,
                    y: ay,
                    claimed: ac
                },
                &[(12, 2), (12, 1), (CLAIMED_WIRE, 9)]
            ),
            tampered(
                &CheckedMul::<4> {
                    x: mx,
                    y: my,
                    claimed: mc
                },
                &[(12, 16), (13, 2), (13, 0), (CLAIMED_WIRE, 16)]
            ),
            tampered(
                &CheckedSub::<4> {
                    x: sx,
                    y: sy,
                    claimed: sc
                },
                &[(12, 2), (12, 0), (CLAIMED_WIRE, 6)]
            ),
            tampered(
                &Mul::<4, 8> {
                    x: mx,
                    y: my,
                    claimed: mc
                },
                &[(12, 16), (CLAIMED_WIRE, 16)]
            ),
            tampered(
                &Add::<4, 5> {
                    x: mx,
                    y: my,
                    claimed: Field::from(8u64)
                },
                &[(CLAIMED_WIRE, 9)]
            ),
        ],
        [
            vec![
                Err(breaks_rule(10, ADD_RULE)),
                Err(breaks_rule(14, ADD_RULE)),
                Err(breaks_rule(15, RULE)),
            ],
            vec![
                unlabelled(10),
                Err(breaks_rule(11, MUL_RULE)),
                Err(breaks_rule(15, MUL_RULE)),
                Err(breaks_rule(16, RULE)),
            ],
            vec![
                Err(breaks_rule(10, SUB_RULE)),
                Err(breaks_rule(14, SUB_RULE)),
                Err(breaks_rule(15, RULE)),
            ],
            vec![unlabelled(10), Err(breaks_rule(11, RULE))],
            vec![Err(breaks_rule(10, RULE))],
        ]
    );
}

struct Free;

impl Visit for Free {
    type Output = PrivateVariableReport;

    fn visit<F: Fixture>(&self, fixture: &F) -> PrivateVariableReport {
        check_private_variables(fixture)
    }
}

#[test]
fn no_private_variable_is_free_in_any_operation() {
    let (x, y) = (Fr::from(4u64), Fr::from(3u64));
    let wide = || edges().into_iter().filter(|edge| edge.fits);
    assert_eq!(
        (
            OPS.map(|op| visit_4(&Free, op, x, y, result(op, x, y))),
            wide()
                .map(|edge| (edge.name, edge.visit(&Free)))
                .collect::<Vec<_>>(),
        ),
        (
            OPS.map(|op| {
                let variables = witness(op, 4, x, y, result(op, x, y)).len() - 1;
                no_free_variable(constraints(op, 4), variables)
            }),
            wide()
                .map(|edge| {
                    let claimed = result(edge.op, edge.x, edge.y);
                    let variables = witness(edge.op, edge.bits, edge.x, edge.y, claimed).len() - 1;
                    (
                        edge.name,
                        no_free_variable(constraints(edge.op, edge.bits as usize), variables),
                    )
                })
                .collect::<Vec<_>>()
        )
    );
}

#[test]
fn sum_rows_bind_every_operand_and_the_claim() {
    for values in [[0u64, 0, 0], [1, 7, 15], [15, 15, 15]] {
        let total: u64 = values.iter().sum();
        let fixture = Sum::<4, 6> {
            values: values.map(Field::from),
            claimed: total.into(),
        };
        assert_eq!(check_constraints(&fixture), Ok(16));
        assert_eq!(first_unsatisfied::<Sum<4, 6>>(&assignment(&fixture)), None);
        assert_eq!(
            check_tampered(&fixture, 4, (total + 1).into()),
            Err(breaks_rule(15, RULE))
        );
        assert_eq!(check_private_variables(&fixture), no_free_variable(16, 16));
    }
}
