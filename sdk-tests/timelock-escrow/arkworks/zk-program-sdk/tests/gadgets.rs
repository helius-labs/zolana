use zk_program_sdk::{
    circuit::{
        assert_in, constant, from_bits_le, is_in, one_hot, select_index, value, Arithmetic, Assert,
        Asset, Bits, Bool, Bytes, CircuitVar, Compare, ConstraintSystem, Field,
    },
    conversion::Allocator,
    RelationError,
};

type Gadget<'a> = &'a dyn Fn(&[CircuitVar]) -> Result<Vec<CircuitVar>, RelationError>;

#[derive(Debug, PartialEq)]
struct Outcome {
    native: Result<Vec<Field>, String>,
    r1cs: Result<(Vec<Field>, bool), String>,
}

fn f(value: u64) -> Field {
    Field::from(value)
}

fn fs(values: &[u64]) -> Vec<Field> {
    values.iter().copied().map(f).collect()
}

fn run(inputs: &[Field], gadget: Gadget) -> Outcome {
    let constants: Vec<CircuitVar> = inputs.iter().copied().map(constant).collect();
    let native = gadget(&constants)
        .and_then(|outputs| outputs.iter().map(value).collect())
        .map_err(|error| error.to_string());
    let cs = ConstraintSystem::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    let r1cs = (|| {
        let witnesses = inputs
            .iter()
            .map(|input| allocator.private_input(&constant(*input)))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = gadget(&witnesses)?
            .iter()
            .map(value)
            .collect::<Result<Vec<_>, _>>()?;
        let satisfied = cs.is_satisfied()?;
        Ok::<_, RelationError>((if satisfied { outputs } else { vec![] }, satisfied))
    })()
    .map_err(|error| error.to_string());
    Outcome { native, r1cs }
}

fn holds(values: &[Field]) -> Outcome {
    Outcome {
        native: Ok(values.to_vec()),
        r1cs: Ok((values.to_vec(), true)),
    }
}

fn violated(message: &str) -> Outcome {
    Outcome {
        native: Err(message.to_string()),
        r1cs: Ok((vec![], false)),
    }
}

fn refused(message: &str) -> Outcome {
    Outcome {
        native: Err(message.to_string()),
        r1cs: Err(message.to_string()),
    }
}

fn bools(flags: &[Bool]) -> Vec<CircuitVar> {
    flags.iter().map(Bool::var).collect()
}

fn operands(inputs: &[CircuitVar]) -> (CircuitVar, CircuitVar) {
    let mut inputs = inputs.iter().cloned();
    (
        inputs.next().expect("left operand"),
        inputs.next().expect("right operand"),
    )
}

fn only(inputs: &[CircuitVar]) -> CircuitVar {
    inputs.first().cloned().expect("one input")
}

fn minus(value: u64) -> Field {
    -f(value)
}

#[test]
fn comparisons_follow_integer_order() {
    let pairs = [
        (3, 5),
        (5, 5),
        (7, 5),
        (0, u64::MAX),
        (u64::MAX, 0),
        (u64::MAX, u64::MAX),
    ];
    let outcomes: Vec<Outcome> = pairs
        .iter()
        .map(|(left, right)| {
            run(&fs(&[*left, *right]), &|inputs| {
                let (left, right) = operands(inputs);
                Ok(vec![
                    left.is_less_than(&right, 64)?.var(),
                    left.is_less_or_equal(&right, 64)?.var(),
                    left.is_greater_than(&right, 64)?.var(),
                    left.is_greater_or_equal(&right, 64)?.var(),
                    left.min(&right, 64)?,
                    left.max(&right, 64)?,
                ])
            })
        })
        .collect();
    let expected: Vec<Outcome> = pairs
        .iter()
        .map(|(left, right)| {
            holds(&fs(&[
                u64::from(left < right),
                u64::from(left <= right),
                u64::from(left > right),
                u64::from(left >= right),
                *left.min(right),
                *left.max(right),
            ]))
        })
        .collect();

    assert_eq!(outcomes, expected);
}

#[test]
fn comparisons_refuse_operands_wider_than_the_range() {
    let less_than = |inputs: &[CircuitVar]| {
        let (left, right) = operands(inputs);
        Ok(vec![left.is_less_than(&right, 64)?.var()])
    };

    assert_eq!(
        (
            run(&[f(u64::MAX) + f(1), f(0)], &less_than),
            run(&[f(0), minus(1)], &less_than),
            run(&[f(0), f(0)], &|inputs| {
                let (left, right) = operands(inputs);
                Ok(vec![left.is_less_than(&right, 252)?.var()])
            }),
            run(&[f(0), f(0)], &|inputs| {
                let (left, right) = operands(inputs);
                Ok(vec![left.is_less_than(&right, 253)?.var()])
            }),
        ),
        (
            violated("a value does not fit in 64 bits"),
            violated("a value does not fit in 64 bits"),
            holds(&[f(0)]),
            refused("a range check over 253 bits covers the whole field"),
        )
    );
}

#[test]
fn comparison_asserts_hold_exactly_on_their_relation() {
    let check = |inputs: &[CircuitVar], index: usize| -> Result<Vec<CircuitVar>, RelationError> {
        let (left, right) = operands(inputs);
        match index {
            0 => left.assert_less_than(&right, 64, "less than"),
            1 => left.assert_less_or_equal(&right, 64, "less or equal"),
            2 => left.assert_greater_than(&right, 64, "greater than"),
            _ => left.assert_greater_or_equal(&right, 64, "greater or equal"),
        }?;
        Ok(vec![])
    };
    let cases: [(u64, u64); 3] = [(4, 5), (5, 5), (6, 5)];
    let outcomes: Vec<Vec<Outcome>> = cases
        .iter()
        .map(|(left, right)| {
            (0..4)
                .map(|index| run(&fs(&[*left, *right]), &|inputs| check(inputs, index)))
                .collect()
        })
        .collect();

    assert_eq!(
        outcomes,
        vec![
            vec![
                holds(&[]),
                holds(&[]),
                violated("greater than"),
                violated("greater or equal"),
            ],
            vec![
                violated("less than"),
                holds(&[]),
                violated("greater than"),
                holds(&[]),
            ],
            vec![
                violated("less than"),
                violated("less or equal"),
                holds(&[]),
                holds(&[]),
            ],
        ]
    );
}

#[test]
fn comparison_asserts_reject_wrapped_operands() {
    assert_eq!(
        (
            run(&[f(5), minus(1)], &|inputs| {
                let (left, right) = operands(inputs);
                left.assert_less_or_equal(&right, 64, "at most")?;
                Ok(vec![])
            }),
            run(&[minus(1), f(0)], &|inputs| {
                let (left, right) = operands(inputs);
                right.assert_greater_or_equal(&left, 64, "at least")?;
                Ok(vec![])
            }),
            run(&[f(u64::MAX), f(u64::MAX)], &|inputs| {
                let (left, right) = operands(inputs);
                left.assert_less_than(&(right + constant(1u64)), 64, "below")?;
                Ok(vec![])
            }),
        ),
        (
            violated("at most"),
            violated("a value does not fit in 64 bits"),
            holds(&[]),
        )
    );
}

#[test]
fn assert_in_range_is_inclusive() {
    let in_range = |value: u64| {
        run(&fs(&[value]), &|inputs| {
            let value = only(inputs);
            value.assert_in_range(&constant(5u64), &constant(9u64), 64, "in 5..=9")?;
            Ok(vec![])
        })
    };

    assert_eq!(
        [4, 5, 9, 10].map(in_range),
        [
            violated("in 5..=9"),
            holds(&[]),
            holds(&[]),
            violated("in 5..=9"),
        ]
    );
}

#[test]
fn comparisons_cost_one_decomposition_per_range() {
    let count = |gadget: Gadget| {
        let cs = ConstraintSystem::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let inputs = [
            allocator.private_input(&constant(3u64)).unwrap(),
            allocator.private_input(&constant(5u64)).unwrap(),
        ];
        gadget(&inputs).unwrap();
        (cs.is_satisfied().unwrap(), cs.num_constraints())
    };

    assert_eq!(
        (
            count(&|inputs| {
                let (left, right) = operands(inputs);
                Ok(vec![left.is_less_than(&right, 64)?.var()])
            }),
            count(&|inputs| {
                let (left, right) = operands(inputs);
                left.assert_less_than(&right, 64, "less than")?;
                Ok(vec![])
            }),
            count(&|inputs| {
                let (left, _) = operands(inputs);
                left.assert_less_than(&constant(9u64), 64, "less than")?;
                Ok(vec![])
            }),
        ),
        ((true, 65 + 65 + 66), (true, 65 + 65), (true, 65 + 65))
    );
}

#[test]
fn zero_checks() {
    let zero_checks = |value: u64| {
        (
            run(&fs(&[value]), &|inputs| {
                let value = only(inputs);
                Ok(vec![value.is_zero()?.var()])
            }),
            run(&fs(&[value]), &|inputs| {
                let value = only(inputs);
                value.assert_zero("is zero")?;
                Ok(vec![])
            }),
            run(&fs(&[value]), &|inputs| {
                let value = only(inputs);
                value.assert_nonzero("is nonzero")?;
                Ok(vec![])
            }),
        )
    };

    assert_eq!(
        (zero_checks(0), zero_checks(7)),
        (
            (
                holds(&[f(1)]),
                holds(&[]),
                Outcome {
                    native: Err("is nonzero".to_string()),
                    r1cs: Err("an assignment for a variable could not be computed".to_string()),
                },
            ),
            (holds(&[f(0)]), violated("is zero"), holds(&[])),
        )
    );
}

#[test]
fn conditional_asserts_only_bind_when_the_condition_holds() {
    let equal_if = |left: u64, right: u64, condition: u64| {
        run(&fs(&[left, right, condition]), &|inputs| {
            let mut inputs = inputs.iter();
            let left = inputs.next().expect("left");
            let right = inputs.next().expect("right");
            let condition = Bool::from_var(inputs.next().expect("condition"))?;
            left.assert_equal_if(right, &condition, "equal when set")?;
            Ok(vec![])
        })
    };
    let true_if = |flag: u64, condition: u64| {
        run(&fs(&[flag, condition]), &|inputs| {
            let (flag, condition) = operands(inputs);
            Bool::from_var(&flag)?.assert_true_if(&Bool::from_var(&condition)?, "true when set")?;
            Ok(vec![])
        })
    };

    assert_eq!(
        (
            equal_if(3, 4, 0),
            equal_if(3, 4, 1),
            equal_if(3, 3, 1),
            true_if(0, 0),
            true_if(0, 1),
            true_if(1, 1),
        ),
        (
            holds(&[]),
            violated("equal when set"),
            holds(&[]),
            holds(&[]),
            violated("true when set"),
            holds(&[]),
        )
    );
}

#[test]
fn bool_operations_follow_their_truth_tables() {
    let table: Vec<Outcome> = [(0, 0), (0, 1), (1, 0), (1, 1)]
        .iter()
        .map(|(left, right)| {
            run(&fs(&[*left, *right]), &|inputs| {
                let (left, right) = operands(inputs);
                let left = Bool::from_var(&left)?;
                let right = Bool::from_var(&right)?;
                Ok(bools(&[
                    left.and(&right),
                    left.or(&right),
                    left.xor(&right),
                    left.nand(&right),
                    left.implies(&right),
                    left.is_equal(&right)?,
                    Bool::all(&[left.clone(), right.clone(), left.clone()])?,
                    Bool::any(&[left.clone(), right.clone(), left.clone()])?,
                ]))
            })
        })
        .collect();
    let expected: Vec<Outcome> = [(false, false), (false, true), (true, false), (true, true)]
        .iter()
        .map(|(left, right)| {
            holds(&fs(&[
                u64::from(*left && *right),
                u64::from(*left || *right),
                u64::from(left != right),
                u64::from(!(*left && *right)),
                u64::from(!*left || *right),
                u64::from(left == right),
                u64::from(*left && *right),
                u64::from(*left || *right),
            ]))
        })
        .collect();

    assert_eq!(table, expected);
}

#[test]
fn bools_are_checked_and_asserted() {
    let from_var = |value: u64| {
        run(&fs(&[value]), &|inputs| {
            let value = only(inputs);
            Ok(vec![Bool::from_var(&value)?.var()])
        })
    };
    let asserted = |value: u64| {
        run(&fs(&[value]), &|inputs| {
            let value = only(inputs);
            let flag = Bool::from_var(&value)?;
            flag.assert_true("is true")?;
            flag.not().assert_false("is not false")?;
            Ok(vec![])
        })
    };

    assert_eq!(
        (
            from_var(1),
            from_var(2),
            asserted(1),
            asserted(0),
            (
                value(&Bool::all(&[]).unwrap().var()).unwrap(),
                value(&Bool::any(&[]).unwrap().var()).unwrap(),
            ),
        ),
        (
            holds(&[f(1)]),
            violated("a value is neither 0 nor 1"),
            holds(&[]),
            violated("is true"),
            (f(1), f(0)),
        )
    );
}

#[test]
fn bits_decompose_and_recompose() {
    assert_eq!(
        (
            run(&fs(&[0b1011]), &|inputs| {
                let value = only(inputs);
                let bits = value.to_bits_le::<4>()?;
                Ok([bools(&bits), vec![from_bits_le(&bits)]].concat())
            }),
            run(&fs(&[8]), &|inputs| {
                let value = only(inputs);
                Ok(bools(&value.to_bits_le::<3>()?))
            }),
        ),
        (
            holds(&fs(&[1, 1, 0, 1, 0b1011])),
            violated("a value does not fit in 3 bits"),
        )
    );
}

#[test]
fn bytes_convert_to_and_from_a_var() {
    let from_var = |value: u64| {
        run(&fs(&[value]), &|inputs| {
            let value = only(inputs);
            let bytes = Bytes::<2>::from_var(&value)?;
            Ok([
                bytes.bytes().to_vec(),
                vec![
                    bytes.to_var()?,
                    bytes.is_equal(&Bytes::constant(&[0x12, 0x34]))?.var(),
                    bytes.is_equal(&Bytes::constant(&[0x12, 0x35]))?.var(),
                ],
            ]
            .concat())
        })
    };

    assert_eq!(
        (
            from_var(0x1234),
            from_var(0x1_0000),
            Bytes::<32>::default()
                .to_var()
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Bytes::<32>::from_var(&constant(0u64))
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Bytes::<31>::from_var(&constant(0u64))
                .map(|_| ())
                .map_err(|e| e.to_string()),
        ),
        (
            holds(&fs(&[0x12, 0x34, 0x1234, 1, 0])),
            violated("a value does not fit in 16 bits"),
            Err("a range check over 256 bits covers the whole field".to_string()),
            Err("a range check over 256 bits covers the whole field".to_string()),
            Ok(()),
        )
    );
}

#[test]
fn integer_arithmetic_refuses_overflow_underflow_and_zero_divisors() {
    let binary = |left: u64, right: u64, operation: usize| {
        run(&fs(&[left, right]), &move |inputs| {
            let (left, right) = operands(inputs);
            Ok(match operation {
                0 => vec![left.checked_add(&right, 64)?],
                1 => vec![left.checked_sub(&right, 64)?],
                2 => vec![left.checked_mul(&right, 64)?],
                _ => {
                    let (quotient, remainder) = left.div_rem(&right, 64)?;
                    vec![quotient, remainder]
                }
            })
        })
    };

    assert_eq!(
        (
            binary(u64::MAX - 1, 1, 0),
            binary(u64::MAX, 1, 0),
            binary(5, 3, 1),
            binary(3, 5, 1),
            binary(1 << 32, 1 << 31, 2),
            binary(1 << 32, 1 << 32, 2),
            binary(17, 5, 3),
            binary(u64::MAX, 1, 3),
            binary(17, 0, 3),
            constant(0u64)
                .checked_mul(&constant(0u64), 127)
                .map(|_| ())
                .map_err(|e| e.to_string()),
        ),
        (
            holds(&[f(u64::MAX)]),
            violated("an operation on 64-bit integers overflows"),
            holds(&[f(2)]),
            violated("a subtraction on 64-bit integers underflows"),
            holds(&[f(1 << 63)]),
            violated("an operation on 64-bit integers overflows"),
            holds(&fs(&[3, 2])),
            holds(&fs(&[u64::MAX, 0])),
            refused("a division by zero"),
            Err("a range check over 127 bits covers the whole field".to_string()),
        )
    );
}

#[test]
fn field_arithmetic() {
    let unary = |input: u64, operation: usize| {
        run(&fs(&[input]), &move |inputs| {
            let input = only(inputs);
            Ok(match operation {
                0 => vec![input.inverse()? * &input],
                1 => vec![constant(21u64).div(&input)?],
                _ => vec![input.pow(5)?],
            })
        })
    };

    assert_eq!(
        (
            unary(7, 0),
            unary(0, 0),
            unary(7, 1),
            unary(0, 1),
            unary(3, 2)
        ),
        (
            holds(&[f(1)]),
            refused("a division by zero"),
            holds(&[f(3)]),
            refused("a division by zero"),
            holds(&[f(243)]),
        )
    );
}

#[test]
fn select_picks_composite_values() {
    let mint = [7u8; 32];
    let selected = |condition: u64| {
        run(&fs(&[condition]), &|inputs| {
            let condition = only(inputs);
            let condition = Bool::from_var(&condition)?;
            let asset = condition.select(&Asset::constant(&mint.into()), &Asset::sol());
            let pair = condition.select(
                &[constant(1u64), constant(2u64)],
                &[constant(3u64), constant(4u64)],
            );
            Ok([
                vec![
                    asset.hash()?,
                    asset.is_equal(&Asset::sol())?.var(),
                    condition
                        .select(&Bool::constant(false), &Bool::constant(true))
                        .var(),
                ],
                pair.to_vec(),
            ]
            .concat())
        })
    };
    let mint_hash = value(&Asset::constant(&mint.into()).hash().unwrap()).unwrap();
    let sol_hash = value(&Asset::sol().hash().unwrap()).unwrap();

    assert_eq!(
        (selected(1), selected(0)),
        (
            holds(&[mint_hash, f(0), f(0), f(1), f(2)]),
            holds(&[sol_hash, f(1), f(1), f(3), f(4)]),
        )
    );
}

#[test]
fn indexing_by_a_var_selects_one_item() {
    let items = [constant(10u64), constant(20u64), constant(30u64)];
    let lookup = |index: u64| {
        run(&fs(&[index]), &|inputs| {
            let index = only(inputs);
            Ok([
                vec![select_index(&items, &index)?],
                bools(&one_hot::<3>(&index)?),
            ]
            .concat())
        })
    };

    assert_eq!(
        (lookup(0), lookup(2), lookup(3)),
        (
            holds(&fs(&[10, 1, 0, 0])),
            holds(&fs(&[30, 0, 0, 1])),
            violated("an index is outside an array of 3 items"),
        )
    );
}

#[test]
fn membership_in_a_set() {
    let set = [constant(10u64), constant(20u64), constant(30u64)];
    let member = |value: u64| {
        (
            run(&fs(&[value]), &|inputs| {
                let value = only(inputs);
                Ok(vec![is_in(&value, &set)?.var()])
            }),
            run(&fs(&[value]), &|inputs| {
                let value = only(inputs);
                assert_in(&value, &set, "in the set")?;
                Ok(vec![])
            }),
        )
    };

    assert_eq!(
        (
            member(20),
            member(25),
            run(&[], &|_| Ok(vec![is_in(&constant(1u64), &[])?.var()]))
        ),
        (
            (holds(&[f(1)]), holds(&[])),
            (holds(&[f(0)]), violated("in the set")),
            holds(&[f(0)]),
        )
    );
}

#[test]
fn arrays_compare_element_wise() {
    let equal = |left: [u64; 2], right: [u64; 2]| {
        run(&fs(&[left, right].concat()), &|inputs| {
            let mut inputs = inputs.iter().cloned();
            let mut next = || inputs.next().expect("input");
            let left = [next(), next()];
            let right = [next(), next()];
            let flag = left.is_equal(&right)?;
            left.assert_not_equal(&[constant(0u64), constant(0u64)], "not all zero")?;
            Ok(vec![flag.var()])
        })
    };

    assert_eq!(
        (
            equal([1, 2], [1, 2]),
            equal([1, 2], [1, 3]),
            equal([0, 0], [0, 0])
        ),
        (holds(&[f(1)]), holds(&[f(0)]), violated("not all zero"),)
    );
}
