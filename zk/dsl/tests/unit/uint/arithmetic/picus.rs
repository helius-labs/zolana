#![cfg(feature = "external-tools")]

use std::time::Duration;

use super::{
    external::compiled,
    fixtures::{Add, CheckedAdd, CheckedMul, CheckedSub, Mul, CLAIMED_WIRE},
};
use crate::{
    harness::{picus::Verdict, WorkDir},
    uint::picus_form::claim_verdicts,
};

const LIMIT: Duration = Duration::from_secs(20);

#[test]
fn picus_checks_arithmetic_claims_with_a_bounded_solver_budget() {
    let work = WorkDir::new("uint-arithmetic-picus");
    let claimed = ["main.claimed"];
    let verdicts = [
        claim_verdicts::<Add<4, 5>>(
            &work,
            "add-4",
            &[CLAIMED_WIRE],
            &compiled("add_4"),
            &claimed,
            LIMIT,
        ),
        claim_verdicts::<Mul<4, 8>>(
            &work,
            "mul-4",
            &[CLAIMED_WIRE],
            &compiled("mul_4"),
            &claimed,
            LIMIT,
        ),
        claim_verdicts::<CheckedAdd<4>>(
            &work,
            "checked-add-4",
            &[CLAIMED_WIRE],
            &compiled("checked_add_4"),
            &claimed,
            LIMIT,
        ),
        claim_verdicts::<CheckedMul<4>>(
            &work,
            "checked-mul-4",
            &[CLAIMED_WIRE],
            &compiled("checked_mul_4"),
            &claimed,
            LIMIT,
        ),
        claim_verdicts::<CheckedSub<4>>(
            &work,
            "checked-sub-4",
            &[CLAIMED_WIRE],
            &compiled("checked_sub_4"),
            &claimed,
            LIMIT,
        ),
        claim_verdicts::<CheckedAdd<64>>(
            &work,
            "checked-add-64",
            &[CLAIMED_WIRE],
            &compiled("checked_add_64"),
            &claimed,
            LIMIT,
        ),
        claim_verdicts::<CheckedMul<64>>(
            &work,
            "checked-mul-64",
            &[CLAIMED_WIRE],
            &compiled("checked_mul_64"),
            &claimed,
            LIMIT,
        ),
        claim_verdicts::<CheckedSub<64>>(
            &work,
            "checked-sub-64",
            &[CLAIMED_WIRE],
            &compiled("checked_sub_64"),
            &claimed,
            LIMIT,
        ),
    ];
    for (index, (sdk, circom)) in verdicts.into_iter().enumerate() {
        eprintln!("Uint arithmetic Picus {index}: SDK={sdk:?}, circom={circom:?}");
        assert_ne!(sdk, Verdict::Unsafe);
        assert_ne!(circom, Verdict::Unsafe);
    }
}

#[test]
fn picus_checks_sum_determinism() {
    use super::fixtures::Sum;
    let work = WorkDir::new("uint-sum-picus");
    let (sdk, circom) = claim_verdicts::<Sum<4, 6>>(
        &work,
        "sum",
        &[4],
        &compiled("sum_4"),
        &["main.claimed"],
        LIMIT,
    );
    eprintln!("Uint sum Picus: SDK={sdk:?}, circom={circom:?}");
    assert_ne!(sdk, Verdict::Unsafe);
    assert_ne!(circom, Verdict::Unsafe);
}
