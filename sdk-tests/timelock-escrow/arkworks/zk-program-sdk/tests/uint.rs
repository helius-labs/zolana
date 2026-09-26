use zk_program_sdk::{
    circuit::{value, Assert, Bool, CircuitSystem, CircuitVar, ConstraintSystem, Field, Uint},
    conversion::{Allocator, FromCircuit, ProofInput},
    RelationError,
};

fn native<const BITS: u32>(value: u64) -> Uint<BITS> {
    Uint::constant(value).unwrap()
}

fn number<const BITS: u32>(uint: &Uint<BITS>) -> Field {
    value(&uint.var()).unwrap()
}

fn truth(bool: &Bool) -> Field {
    value(&bool.var()).unwrap()
}

fn allocated(cs: &CircuitSystem, value: u64) -> CircuitVar {
    Field::from(value)
        .instantiate(&Allocator::R1cs(cs.clone()))
        .unwrap()
}

fn uint<const BITS: u32>(cs: &CircuitSystem, value: u64) -> Uint<BITS> {
    Uint::from_var(&allocated(cs, value), "the test value is in range").unwrap()
}

fn cost<T>(cs: &CircuitSystem, operation: impl FnOnce() -> T) -> (usize, T) {
    let before = cs.num_constraints();
    let result = operation();
    (cs.num_constraints() - before, result)
}

fn violated<T: core::fmt::Debug>(result: Result<T, RelationError>) -> Option<&'static str> {
    match result {
        Err(RelationError::Violated(rule)) => Some(rule),
        _ => None,
    }
}

#[test]
fn constants_compute_natively_and_name_the_broken_rule() {
    let a = native::<64>(300);
    let b = native::<64>(200);
    let (quotient, remainder) = a.div_rem::<64, 64>(&native(7), "divides").unwrap();

    assert_eq!(
        (
            number(&a.add::<65>(&b)),
            number(&a.mul::<128>(&b)),
            number(&a.checked_sub(&b, "a covers b").unwrap()),
            number(&a.narrow::<9>("fits in 9 bits").unwrap()),
            number(&a.widen::<128>()),
            number(&Uint::<64>::sum::<66, 3>(&[
                a.clone(),
                b.clone(),
                a.clone()
            ])),
            (number(&quotient), number(&remainder)),
        ),
        (
            Field::from(500u64),
            Field::from(60_000u64),
            Field::from(100u64),
            Field::from(300u64),
            Field::from(300u64),
            Field::from(800u64),
            (Field::from(42u64), Field::from(6u64)),
        )
    );
    assert_eq!(
        (
            violated(b.checked_sub(&a, "b is below a")),
            violated(a.narrow::<8>("300 needs 9 bits")),
            violated(a.assert_less_or_equal(&b, "a is above b")),
            violated(a.assert_less_than(&a, "a is not below itself")),
            violated(a.div_rem::<64, 64>(&native(0), "divides by zero")),
            violated(a.div_rem::<4, 64>(&native(1), "the quotient needs 9 bits")),
            violated(native::<64>(0).assert_not_zero("zero")),
            violated(a.assert_equal(&b, "a is b")),
            Uint::<8>::constant(256)
                .err()
                .map(|error| error.to_string()),
        ),
        (
            Some("b is below a"),
            Some("300 needs 9 bits"),
            Some("a is above b"),
            Some("a is not below itself"),
            Some("divides by zero"),
            Some("the quotient needs 9 bits"),
            Some("zero"),
            Some("a is b"),
            Some("a value does not fit in 8 bits".to_string()),
        )
    );
}

#[test]
fn constant_comparisons_are_constant_bools() {
    let a = native::<64>(300);
    let b = native::<64>(200);

    assert_eq!(
        [
            truth(&a.is_less_or_equal(&b).unwrap()),
            truth(&b.is_less_or_equal(&a).unwrap()),
            truth(&a.is_less_or_equal(&a).unwrap()),
            truth(&a.is_less_than(&a).unwrap()),
            truth(&b.is_less_than(&a).unwrap()),
            truth(&a.is_equal(&a.widen::<128>()).unwrap()),
            truth(&native::<64>(0).is_zero().unwrap()),
        ],
        [0u64, 1, 1, 0, 1, 1, 1].map(Field::from)
    );
}

#[test]
fn each_operation_costs_its_documented_constraints() {
    let cs = ConstraintSystem::new_ref();
    let (from_var, a) = cost(&cs, || uint::<64>(&cs, 300));
    let b = uint::<64>(&cs, 200);
    let seven = uint::<64>(&cs, 7);
    let (add, sum) = cost(&cs, || a.add::<65>(&b));
    let (mul, product) = cost(&cs, || a.mul::<128>(&b));
    let (checked_sub, difference) = cost(&cs, || a.checked_sub(&b, "a covers b").unwrap());
    let (narrow, narrowed) = cost(&cs, || a.narrow::<9>("fits in 9 bits").unwrap());
    let (widen, widened) = cost(&cs, || a.widen::<128>());
    let (less_or_equal, below) = cost(&cs, || b.is_less_or_equal(&a).unwrap());
    let (less_than, not_below) = cost(&cs, || a.is_less_than(&b).unwrap());
    let (assert_ordered, ()) = cost(&cs, || b.assert_less_than(&a, "b is below a").unwrap());
    let (is_equal, equal) = cost(&cs, || a.is_equal(&b).unwrap());
    let (is_zero, zero) = cost(&cs, || a.is_zero().unwrap());
    let (not_zero, ()) = cost(&cs, || a.assert_not_zero("a is not zero").unwrap());
    let (total_cost, total) = cost(&cs, || {
        Uint::<64>::sum::<66, 3>(&[a.clone(), b.clone(), a.clone()])
    });
    let (div_rem, (quotient, remainder)) = cost(&cs, || {
        a.div_rem::<64, 64>(&seven, "divides by seven").unwrap()
    });
    let expectations = [
        sum.assert_equal(&native::<65>(500), "sum"),
        product.assert_equal(&native::<128>(60_000), "product"),
        difference.assert_equal(&native::<64>(100), "difference"),
        narrowed.assert_equal(&native::<9>(300), "narrowed"),
        widened.assert_equal(&native::<128>(300), "widened"),
        below.assert_equal(&Bool::constant(true), "below"),
        not_below.assert_equal(&Bool::constant(false), "not below"),
        equal.assert_equal(&Bool::constant(false), "equal"),
        zero.assert_equal(&Bool::constant(false), "zero"),
        total.assert_equal(&native::<66>(800), "total"),
        quotient.assert_equal(&native::<64>(42), "quotient"),
        remainder.assert_equal(&native::<64>(6), "remainder"),
    ];

    assert_eq!(
        (
            [
                from_var,
                add,
                mul,
                checked_sub,
                narrow,
                widen,
                less_or_equal,
                less_than,
                assert_ordered,
                is_equal,
                is_zero,
                not_zero,
                total_cost,
                div_rem,
            ],
            expectations.iter().all(Result::is_ok),
            cs.is_satisfied().unwrap(),
        ),
        (
            [65, 0, 1, 65, 10, 0, 66, 66, 65, 2, 2, 1, 0, 196],
            true,
            true
        )
    );
}

#[test]
fn a_broken_rule_leaves_the_constraints_unsatisfied() {
    let unsatisfied = |build: fn(&CircuitSystem) -> Result<(), RelationError>| {
        let cs = ConstraintSystem::new_ref();
        build(&cs).unwrap();
        !cs.is_satisfied().unwrap()
    };

    assert_eq!(
        [
            unsatisfied(|cs| {
                let too_large = (Field::from(u64::MAX) + Field::from(1u64))
                    .instantiate(&Allocator::R1cs(cs.clone()))?;
                Uint::<64>::from_var(&too_large, "fits in 64 bits").map(|_| ())
            }),
            unsatisfied(|cs| {
                uint::<64>(cs, 200)
                    .checked_sub(&uint(cs, 300), "200 is below 300")
                    .map(|_| ())
            }),
            unsatisfied(|cs| uint::<64>(cs, 300)
                .narrow::<8>("300 needs 9 bits")
                .map(|_| ())),
            unsatisfied(|cs| uint::<64>(cs, 3).assert_less_than(&uint(cs, 3), "3 is not below 3")),
            unsatisfied(|cs| {
                uint::<64>(cs, 3)
                    .div_rem::<64, 64>(&uint(cs, 0), "divides by zero")
                    .map(|_| ())
            }),
            unsatisfied(|cs| {
                uint::<64>(cs, 300)
                    .div_rem::<4, 64>(&uint(cs, 1), "the quotient needs 9 bits")
                    .map(|_| ())
            }),
            unsatisfied(|cs| uint::<64>(cs, 0).assert_not_zero("zero")),
            unsatisfied(|cs| {
                let bit = uint::<64>(cs, 300).is_less_or_equal(&uint(cs, 200))?;
                bit.assert_equal(&Bool::constant(true), "300 is at most 200")
            }),
        ],
        [true; 8]
    );
}

#[test]
fn a_bool_selects_between_uints_and_becomes_a_bit() {
    let cs = ConstraintSystem::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    let chosen = true.instantiate(&allocator).unwrap();
    let a = uint::<64>(&cs, 300);
    let b = uint::<64>(&cs, 200);
    let (select, selected) = cost(&cs, || chosen.select(&a, &b));
    let counted = b.add::<65>(&chosen.to_uint().widen::<64>());
    let checks = [
        selected.assert_equal(&native::<64>(300), "selected"),
        counted.assert_equal(&native::<65>(201), "counted"),
        Bool::constant(false)
            .select(&native::<64>(1), &native::<64>(2))
            .assert_equal(&native::<64>(2), "a constant selection"),
    ];

    assert_eq!(
        (
            select,
            checks.iter().all(Result::is_ok),
            cs.is_satisfied().unwrap()
        ),
        (1, true, true)
    );
}

#[test]
fn a_field_proof_input_is_an_unchecked_private_value() {
    let native = Field::from(9u64).instantiate(&Allocator::native()).unwrap();

    assert_eq!(Field::from_circuit(&native).unwrap(), Field::from(9u64));
}
