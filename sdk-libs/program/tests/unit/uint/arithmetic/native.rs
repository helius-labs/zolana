use ark_bn254::Fr;
use num_bigint::BigUint;
use zolana_program::circuit::{constant, value, CircuitVar, Field, Uint};

use super::{
    fixtures::{
        result, Add, CheckedAdd, CheckedMul, CheckedSub, Mul, Op, Sum, ADD_RULE, FILE, MUL_RULE,
        RULE, SUB_RULE,
    },
    vectors::{edges, Edge},
};
use crate::uint::rows::{broken, field, integer, max, native, refused, Refused};

fn uint<const BITS: u32>(value: Fr) -> Uint<BITS> {
    Uint::try_from(constant(field(value))).expect("an operand that fits")
}

fn value_of<const BITS: u32>(uint: Uint<BITS>) -> Fr {
    Fr::from(value(&CircuitVar::from(uint)).expect("a constant result"))
}

fn pairs() -> impl Iterator<Item = (u64, u64)> {
    (0..16u64).flat_map(|x| (0..16u64).map(move |y| (x, y)))
}

#[test]
fn at_4_bits_add_mul_and_sum_give_the_integer_result_for_every_operand() {
    let computed: Vec<_> = pairs()
        .map(|(x, y)| {
            let (a, b) = (uint::<4>(Fr::from(x)), uint::<4>(Fr::from(y)));
            let sum = Uint::<4>::sum::<6, 3>(&[a.clone(), b.clone(), a.clone()]);
            (
                value_of(a.add::<5>(&b)),
                value_of(a.mul::<8>(&b)),
                value_of(sum),
            )
        })
        .collect();
    assert_eq!(
        computed,
        pairs()
            .map(|(x, y)| (Fr::from(x + y), Fr::from(x * y), Fr::from(2 * x + y)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn at_the_widest_output_widths_add_mul_and_sum_never_wrap_around_the_modulus() {
    let (max_252, max_251, max_126) = (max(252), max(251), max(126));
    let as_integer = |fr: Fr| integer(fr);
    let two_252 = BigUint::from(1u8) << 252u32;
    let two_251 = BigUint::from(1u8) << 251u32;
    let two_126 = BigUint::from(1u8) << 126u32;
    let one = BigUint::from(1u8);
    assert_eq!(
        [
            as_integer(value_of(
                uint::<252>(max_252).add::<253>(&uint::<252>(max_252))
            )),
            as_integer(value_of(
                uint::<126>(max_126).mul::<252>(&uint::<126>(max_126))
            )),
            as_integer(value_of(Uint::<251>::sum::<253, 3>(&[
                uint::<251>(max_251),
                uint::<251>(max_251),
                uint::<251>(max_251),
            ]))),
        ],
        [
            (&two_252 - &one) * 2u8,
            (&two_126 - &one) * (&two_126 - &one),
            (&two_251 - &one) * 3u8,
        ]
    );
}

fn checked(op: Op, x: u64, y: u64) -> Result<(), Refused> {
    let (x, y) = (Field::from(x), Field::from(y));
    let claimed = field(result(op, x.into(), y.into()));
    match op {
        Op::CheckedAdd => native(&CheckedAdd::<4> { x, y, claimed }),
        Op::CheckedMul => native(&CheckedMul::<4> { x, y, claimed }),
        Op::CheckedSub => native(&CheckedSub::<4> { x, y, claimed }),
        Op::Add | Op::Mul => unreachable!("an unchecked operation"),
    }
}

#[test]
fn at_4_bits_every_checked_operation_holds_exactly_when_the_integer_result_fits() {
    let outcome = |fits: bool, rule| {
        if fits {
            Ok(())
        } else {
            Err(broken(rule, FILE))
        }
    };
    assert_eq!(
        pairs()
            .map(|(x, y)| (
                checked(Op::CheckedAdd, x, y),
                checked(Op::CheckedMul, x, y),
                checked(Op::CheckedSub, x, y),
            ))
            .collect::<Vec<_>>(),
        pairs()
            .map(|(x, y)| (
                outcome(x + y < 16, ADD_RULE),
                outcome(x * y < 16, MUL_RULE),
                outcome(x >= y, SUB_RULE),
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn at_4_bits_every_checked_result_that_fits_is_the_integer_result() {
    let kept = |x: u64, y: u64| {
        let (a, b) = (uint::<4>(Fr::from(x)), uint::<4>(Fr::from(y)));
        let of = |result: Result<Uint<4>, _>| refused(result).map(value_of);
        (
            of(a.checked_add(&b, ADD_RULE)).ok(),
            of(a.checked_mul(&b, MUL_RULE)).ok(),
            of(a.checked_sub(&b, SUB_RULE)).ok(),
        )
    };
    assert_eq!(
        pairs().map(|(x, y)| kept(x, y)).collect::<Vec<_>>(),
        pairs()
            .map(|(x, y)| (
                (x + y < 16).then(|| Fr::from(x + y)),
                (x * y < 16).then(|| Fr::from(x * y)),
                (x >= y).then(|| Fr::from(x - y)),
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn at_64_126_and_252_bits_every_checked_operation_refuses_exactly_past_the_edge() {
    assert_eq!(
        edges()
            .iter()
            .map(|edge| (edge.name, edge.native()))
            .collect::<Vec<_>>(),
        edges()
            .iter()
            .map(|Edge { name, op, fits, .. }| {
                let rule = match op {
                    Op::CheckedAdd => ADD_RULE,
                    Op::CheckedMul => MUL_RULE,
                    _ => SUB_RULE,
                };
                (
                    *name,
                    if *fits {
                        Ok(())
                    } else {
                        Err(broken(rule, FILE))
                    },
                )
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_wrong_claim_breaks_exactly_the_fixture_rule_natively() {
    let (one, two, four) = (Field::from(1u64), Field::from(2u64), Field::from(4u64));
    let refusal = || Err(broken(RULE, FILE));
    assert_eq!(
        [
            native(&Add::<4, 5> {
                x: one,
                y: two,
                claimed: four
            }),
            native(&Mul::<4, 8> {
                x: one,
                y: two,
                claimed: four
            }),
            native(&Sum::<4, 6> {
                values: [one, two, one],
                claimed: two
            }),
            native(&CheckedAdd::<4> {
                x: one,
                y: two,
                claimed: four
            }),
            native(&CheckedMul::<4> {
                x: one,
                y: two,
                claimed: four
            }),
            native(&CheckedSub::<4> {
                x: two,
                y: one,
                claimed: four
            }),
        ],
        [
            refusal(),
            refusal(),
            refusal(),
            refusal(),
            refusal(),
            refusal()
        ]
    );
}

#[test]
fn empty_and_singleton_sums_have_the_integer_identity() {
    assert_eq!(value_of(Uint::<4>::sum::<4, 0>(&[])), Fr::from(0u64));
    for x in 0..16u64 {
        assert_eq!(
            value_of(Uint::<4>::sum::<4, 1>(&[uint::<4>(Fr::from(x))])),
            Fr::from(x)
        );
    }
}
