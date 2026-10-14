use super::{fixtures::*, r1cs::honest};
use crate::harness::fixture::{check_tampered, native};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn random_u64_relations_match_the_integer_reference(x in any::<u64>(), y in any::<u64>(), condition in any::<bool>()) {
        let (x, y) = (u128::from(x), u128::from(y));
        honest(&compare::<64, 0>(x, y)); honest(&compare::<64, 1>(x, y));
        honest(&compare::<64, 2>(x, y)); honest(&compare::<64, 3>(x, y));
        honest(&compare::<64, 4>(x, y)); honest(&compare::<64, 5>(x, y));
        let selected = Selection::<64> { x: x.into(), y: y.into(), condition, claimed: (if condition { x } else { y }).into() };
        honest(&selected);
        prop_assert!(check_tampered(&selected, 4, (u128::from(u64::MAX) + 1).into()).is_err());
        let range = Range::<64> { x: x.into(), low: x.min(y).into(), high: x.max(y).into() };
        honest(&range);
    }
    #[test]
    fn random_u64_divisions_match_integer_quotient_and_remainder(x in any::<u64>(), d in 1..=u64::MAX) {
        let fixture = division::<64, 64, 64>(u128::from(x), u128::from(d));
        honest(&fixture);
        prop_assert!(check_tampered(&fixture, 3, (u128::from(x / d) + 1).into()).is_err());
        prop_assert!(check_tampered(&fixture, 4, (u128::from(x % d) + 1).into()).is_err());
        prop_assert!(native(&division::<64, 64, 64>(u128::from(x), 0)).is_err());
    }
}

fn native_rule<F: zolana_program::ZkCircuit>(fixture: &F, holds: bool, rule: &'static str) {
    assert_eq!(
        native(fixture).map_err(|(name, rule, _)| (name, rule)),
        if holds {
            Ok(())
        } else {
            Err(("CircuitError.RuleBroken", Some(rule)))
        },
    );
}

fn generated_pair<const OP: u8>(x: u64, y: u64) {
    use crate::{
        harness::fixture::{check_constraints, exported},
        uint::rows::low_bits,
    };
    use ark_bn254::Fr;
    use ark_ff::{Field as _, One};
    let holds = pair_holds(OP, x, y);
    let fixture = Pair::<64, OP> {
        x: x.into(),
        y: y.into(),
    };
    native_rule(&fixture, holds, RULE);
    let (x, y) = (Fr::from(x), Fr::from(y));
    let mut candidate = [vec![Fr::one(), x, y], low_bits(x, 64), low_bits(y, 64)].concat();
    if OP == 2 || OP == 3 {
        candidate.extend(low_bits(y, 253));
    }
    if OP < 2 {
        candidate.extend(low_bits(y - x - Fr::from(u64::from(OP == 0)), 64));
    }
    if OP == 3 || OP == 5 {
        candidate.push((x - y).inverse().unwrap_or_default());
    }
    let count = match OP {
        0 | 1 => 195,
        2 | 3 => 385,
        4 | 5 => 131,
        _ => unreachable!("fixture operation"),
    };
    assert_eq!(
        exported::<Pair<64, OP>>().first_unsatisfied(&candidate),
        if holds { None } else { Some(count - 1) }
    );
    if holds {
        assert_eq!(check_constraints(&fixture), Ok(count));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs(x in any::<u64>(), y in any::<u64>()) {
        use ark_bn254::Fr;
        use ark_ff::One;
        use crate::{harness::fixture::{check_constraints, exported}, uint::rows::low_bits};
        // Force equality, strict order in both directions, and a fully random pair.
        for (x, y) in [(x, y), (x, x), (x & !1, x | 1), (x | 1, x & !1)] {
            generated_pair::<0>(x,y); generated_pair::<1>(x,y);
            generated_pair::<2>(x,y); generated_pair::<3>(x,y);
            generated_pair::<4>(x,y); generated_pair::<5>(x,y);
            for condition in [false,true] {
                let fixture = Conditional::<64> { x:x.into(), y:y.into(), condition };
                let holds = !condition || x == y;
                native_rule(&fixture, holds, RULE);
                let (xf, yf) = (Fr::from(x), Fr::from(y));
                let candidate = [vec![Fr::one(),xf,yf,Fr::from(u64::from(condition))], low_bits(xf,64), low_bits(yf,64)].concat();
                prop_assert_eq!(exported::<Conditional<64>>().first_unsatisfied(&candidate), if holds { None } else { Some(131) });
                if holds { prop_assert_eq!(check_constraints(&fixture), Ok(132)); }
            }
        }
    }

    #[test]
    fn random_zero_checks_bind_the_predicate_and_enforce_both_zero_assertions(x in any::<u64>()) {
        use ark_bn254::Fr;
        use ark_ff::{Field as _, One};
        use crate::{harness::fixture::{breaks_rule, check_constraints, exported}, uint::rows::low_bits};
        // Every generated case covers zero and a nonzero value, even after shrinking.
        for x in [0, x | 1, x] {
            let zero = AssertZero::<64,false> { x:x.into() };
            let nonzero = AssertZero::<64,true> { x:x.into() };
            native_rule(&zero, x == 0, RULE);
            native_rule(&nonzero, x != 0, RULE);
            let xf = Fr::from(x);
            let candidate = [vec![Fr::one(),xf],low_bits(xf,64)].concat();
            prop_assert_eq!(exported::<AssertZero<64,false>>().first_unsatisfied(&candidate), if x == 0 { None } else { Some(65) });
            let mut inverse_candidate = candidate;
            inverse_candidate.push(xf.inverse().unwrap_or_default());
            prop_assert_eq!(exported::<AssertZero<64,true>>().first_unsatisfied(&inverse_candidate), if x != 0 { None } else { Some(65) });
            if x == 0 { prop_assert_eq!(check_constraints(&zero), Ok(66)); }
            else { prop_assert_eq!(check_constraints(&nonzero), Ok(66)); }
            let expected = u64::from(x == 0);
            let fixture = Zero::<64> { x:x.into(), claimed:expected.into() };
            honest(&fixture);
            let wrong = Zero::<64> { x:x.into(), claimed:(1-expected).into() };
            native_rule(&wrong, false, CLAIM);
            prop_assert_eq!(check_tampered(&fixture,2,wrong.claimed), Err(breaks_rule(67,CLAIM)));
        }
    }
}
