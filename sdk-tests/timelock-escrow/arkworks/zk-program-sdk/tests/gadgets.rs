use zk_program_sdk::{
    circuit::{
        assert_in, constant, from_bits_le, is_in, one_hot, select_index, value, Arithmetic, Assert,
        Asset, Bits, Bool, Bytes, CircuitVar, Compare, ConstraintSystem, Field, Uint,
    },
    conversion::{Allocator, ProofInput},
    CircuitError,
};

type Gadget<'a> = &'a dyn Fn(&[CircuitVar]) -> Result<Vec<CircuitVar>, CircuitError>;

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
        .and_then(|outputs| outputs.iter().map(value).collect::<Result<Vec<_>, _>>());
    let cs = ConstraintSystem::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    let r1cs = (|| {
        let allocated = inputs
            .iter()
            .map(|input| input.instantiate(&allocator))
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = gadget(&allocated)?;
        let expected = native.as_ref().ok();
        if let Some(expected) = expected {
            for (output, expected) in outputs.iter().zip(expected) {
                output.assert_equal(
                    &constant(*expected),
                    "the constraints compute the native output",
                )?;
            }
        }
        let same_length = expected.is_none_or(|expected| expected.len() == outputs.len());
        let satisfied = cs.is_satisfied()? && same_length;
        let computed = match expected {
            Some(expected) if satisfied => expected.clone(),
            _ => vec![],
        };
        Ok::<_, CircuitError>((computed, satisfied))
    })()
    .map_err(|error| error.to_string());
    Outcome {
        native: native.map_err(|error| error.to_string()),
        r1cs,
    }
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

fn uint<const BITS: u32>(var: &CircuitVar) -> Result<Uint<BITS>, CircuitError> {
    Uint::from_var(var, "an operand fits in its width")
}

fn uint_operands<const BITS: u32>(
    inputs: &[CircuitVar],
) -> Result<(Uint<BITS>, Uint<BITS>), CircuitError> {
    let (left, right) = operands(inputs);
    Ok((uint(&left)?, uint(&right)?))
}

fn widest_ordered() -> Field {
    (0..252).fold(f(1), |power, _| power + power) - f(1)
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
                let (left, right) = uint_operands::<64>(inputs)?;
                Ok(vec![
                    left.is_less_than(&right)?.var(),
                    left.is_less_or_equal(&right)?.var(),
                    right.is_less_than(&left)?.var(),
                    right.is_less_or_equal(&left)?.var(),
                    left.min(&right)?.var(),
                    left.max(&right)?.var(),
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
fn operands_outside_the_width_are_refused() {
    let less_than = |inputs: &[CircuitVar]| {
        let (left, right) = uint_operands::<64>(inputs)?;
        Ok(vec![left.is_less_than(&right)?.var()])
    };

    assert_eq!(
        (
            run(&[f(u64::MAX) + f(1), f(0)], &less_than),
            run(&[f(0), minus(1)], &less_than),
        ),
        (
            violated("an operand fits in its width"),
            violated("an operand fits in its width"),
        )
    );
}

#[test]
fn ordering_holds_at_the_widest_ordered_width() {
    let top = widest_ordered();

    assert_eq!(
        (
            run(&[top, f(0)], &|inputs| {
                let (left, right) = uint_operands::<252>(inputs)?;
                Ok(vec![
                    left.is_less_than(&right)?.var(),
                    right.is_less_than(&left)?.var(),
                ])
            }),
            run(&[f(0), top], &|inputs| {
                let (left, right) = uint_operands::<252>(inputs)?;
                Ok(vec![left.checked_sub(&right, "no underflow")?.var()])
            }),
            run(&[top, f(0)], &|inputs| {
                let (left, right) = uint_operands::<252>(inputs)?;
                left.assert_less_or_equal(&right, "at most")?;
                Ok(vec![])
            }),
            run(&[top, top], &|inputs| {
                let (left, right) = uint_operands::<252>(inputs)?;
                Ok(vec![left.add::<253>(&right).var()])
            }),
        ),
        (
            holds(&fs(&[0, 1])),
            violated("no underflow"),
            violated("at most"),
            holds(&[top + top]),
        )
    );
}

#[test]
fn comparison_asserts_hold_exactly_on_their_relation() {
    let check = |inputs: &[CircuitVar], index: usize| -> Result<Vec<CircuitVar>, CircuitError> {
        let (left, right) = uint_operands::<64>(inputs)?;
        match index {
            0 => left.assert_less_than(&right, "less than"),
            1 => left.assert_less_or_equal(&right, "less or equal"),
            2 => right.assert_less_than(&left, "greater than"),
            _ => right.assert_less_or_equal(&left, "greater or equal"),
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
fn assert_in_range_is_inclusive() {
    let in_range = |value: u64| {
        run(&fs(&[value]), &|inputs| {
            let value = uint::<64>(&only(inputs))?;
            value.assert_in_range(&Uint::constant(5)?, &Uint::constant(9)?, "in 5..=9")?;
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
            f(3).instantiate(&allocator).unwrap(),
            f(5).instantiate(&allocator).unwrap(),
        ];
        gadget(&inputs).unwrap();
        (cs.is_satisfied().unwrap(), cs.num_constraints())
    };

    assert_eq!(
        (
            count(&|inputs| {
                let (left, right) = uint_operands::<64>(inputs)?;
                Ok(vec![left.is_less_than(&right)?.var()])
            }),
            count(&|inputs| {
                let (left, right) = uint_operands::<64>(inputs)?;
                left.assert_less_than(&right, "less than")?;
                Ok(vec![])
            }),
            count(&|inputs| {
                let left = uint::<64>(&only(inputs))?;
                left.assert_less_than(&Uint::constant(9)?, "less than")?;
                Ok(vec![])
            }),
        ),
        ((true, 65 + 65 + 66), (true, 65 + 65 + 65), (true, 65 + 65))
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
            (holds(&[f(1)]), holds(&[]), violated("is nonzero")),
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
            Err(
                "a check over 256 bits is too wide; a circuit value holds at most 253 bits"
                    .to_string()
            ),
            Err(
                "a check over 256 bits is too wide; a circuit value holds at most 253 bits"
                    .to_string()
            ),
            Ok(()),
        )
    );
}

#[test]
fn integer_arithmetic_refuses_underflow_narrowing_and_zero_divisors() {
    let binary = |left: u64, right: u64, operation: usize| {
        run(&fs(&[left, right]), &move |inputs| {
            let (left, right) = uint_operands::<64>(inputs)?;
            Ok(match operation {
                0 => vec![left.add::<65>(&right).var()],
                1 => vec![left.checked_sub(&right, "no underflow")?.var()],
                2 => vec![left.mul::<128>(&right).var()],
                3 => vec![left
                    .add::<65>(&right)
                    .narrow::<64>("fits in 64 bits")?
                    .var()],
                _ => {
                    let (quotient, remainder) = left.div_rem::<64, 64>(&right, "divides")?;
                    vec![quotient.var(), remainder.var()]
                }
            })
        })
    };

    assert_eq!(
        (
            binary(u64::MAX, u64::MAX, 0),
            binary(5, 3, 1),
            binary(3, 5, 1),
            binary(1 << 32, 1 << 32, 2),
            binary(u64::MAX - 1, 1, 3),
            binary(u64::MAX, 1, 3),
            binary(17, 5, 4),
            binary(u64::MAX, 1, 4),
            binary(17, 0, 4),
        ),
        (
            holds(&[f(u64::MAX) + f(u64::MAX)]),
            holds(&[f(2)]),
            violated("no underflow"),
            holds(&[f(1 << 32) * f(1 << 32)]),
            holds(&[f(u64::MAX)]),
            violated("fits in 64 bits"),
            holds(&fs(&[3, 2])),
            holds(&fs(&[u64::MAX, 0])),
            violated("divides"),
        )
    );
}

#[test]
fn field_arithmetic() {
    let unary = |input: u64, operation: usize| {
        run(&fs(&[input]), &move |inputs| {
            let input = only(inputs);
            Ok(match operation {
                0 => vec![input.div(&input)?],
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
