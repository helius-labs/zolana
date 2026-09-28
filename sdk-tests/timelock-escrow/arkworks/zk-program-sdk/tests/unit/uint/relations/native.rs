use super::fixtures::*;
use crate::harness::fixture::native;
use zk_program_sdk::{circuit::Field, ZkCircuit};

fn accepted<F: ZkCircuit>(fixture: &F, holds: bool) {
    assert_eq!(
        native(fixture).map_err(|error| (error.0, error.1)),
        if holds {
            Ok(())
        } else {
            Err(("CircuitError.RuleBroken", Some(RULE)))
        }
    );
}

fn compare_all<const OP: u8>() {
    for x in 0..16u128 {
        for y in 0..16u128 {
            assert_eq!(native(&compare::<4, OP>(x, y)), Ok(()));
        }
    }
}

#[test]
fn all_four_bit_comparisons_min_max_and_equalities_match_integer_semantics() {
    compare_all::<0>();
    compare_all::<1>();
    compare_all::<2>();
    compare_all::<3>();
    compare_all::<4>();
    compare_all::<5>();
}

#[test]
fn every_four_bit_assertion_accepts_exactly_its_integer_relation() {
    for x in 0..16u64 {
        for y in 0..16u64 {
            let pair = (Field::from(x), Field::from(y));
            accepted(
                &Pair::<4, 0> {
                    x: pair.0,
                    y: pair.1,
                },
                x < y,
            );
            accepted(
                &Pair::<4, 1> {
                    x: pair.0,
                    y: pair.1,
                },
                x <= y,
            );
            accepted(
                &Pair::<4, 2> {
                    x: pair.0,
                    y: pair.1,
                },
                x == y,
            );
            accepted(
                &Pair::<4, 3> {
                    x: pair.0,
                    y: pair.1,
                },
                x != y,
            );
            accepted(
                &Pair::<4, 4> {
                    x: pair.0,
                    y: pair.1,
                },
                x == y,
            );
            accepted(
                &Pair::<4, 5> {
                    x: pair.0,
                    y: pair.1,
                },
                x != y,
            );
            for condition in [false, true] {
                accepted(
                    &Conditional::<4> {
                        x: pair.0,
                        y: pair.1,
                        condition,
                    },
                    !condition || x == y,
                );
                assert_eq!(
                    native(&Selection::<4> {
                        x: pair.0,
                        y: pair.1,
                        condition,
                        claimed: Field::from(if condition { x } else { y })
                    }),
                    Ok(())
                );
            }
        }
        accepted(&AssertZero::<4, false> { x: x.into() }, x == 0);
        accepted(&AssertZero::<4, true> { x: x.into() }, x != 0);
        assert_eq!(
            native(&Zero::<4> {
                x: x.into(),
                claimed: u64::from(x == 0).into()
            }),
            Ok(())
        );
        for low in 0..16u64 {
            for high in 0..16u64 {
                accepted(
                    &Range::<4> {
                        x: x.into(),
                        low: low.into(),
                        high: high.into(),
                    },
                    low <= x && x <= high,
                );
            }
        }
    }
}

#[test]
fn division_accepts_exactly_nonzero_divisors_and_fitting_quotients() {
    for x in 0..16u128 {
        for d in 0..16u128 {
            accepted(&division::<4, 4, 4>(x, d), d != 0);
            accepted(
                &division::<4, 2, 4>(x, d),
                x.checked_div(d).is_some_and(|q| q < 4),
            );
        }
    }
    for (x, d) in [
        (0, 1),
        (u128::MAX, 1),
        (u128::MAX, u128::MAX),
        (u128::MAX, 1 << 127),
    ] {
        // A 128-bit quotient plus a 124-bit divisor is within the 252-bit limit.
        if d < (1 << 124) {
            accepted(&division::<128, 128, 124>(x, d), true);
        }
        if x.checked_div(d).is_some_and(|q| q < (1 << 124)) {
            accepted(&division::<128, 124, 128>(x, d), true);
        }
    }
}
