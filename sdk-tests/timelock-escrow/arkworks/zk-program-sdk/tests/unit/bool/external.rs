#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{
        AssertedBinary, AssertedUnary, Choose, Fold, Not, Variables, ALL, ANY, BINARY_ASSERTS,
        GATES, UNARY_ASSERTS,
    },
    vectors::{
        BITS, BOOLEAN_PAIRS, DECEPTIVE_ALL, DECEPTIVE_ANY, FLAGS, NON_BOOLEAN, NON_BOOLEAN_PAIRS,
        TRIPLES, WRONG_CLAIMS,
    },
};
use crate::harness::{
    circom::Compiled,
    circomlib,
    equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
    field::{decimal, field},
    fixture::{assignment, Size},
    iden3::{read_r1cs, write_wtns},
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

pub const GATE_REFERENCES: [&str; 6] = [
    "bool/circom/and.circom",
    "bool/circom/or.circom",
    "bool/circom/xor.circom",
    "bool/circom/nand.circom",
    "bool/circom/implies.circom",
    "bool/circom/is_equal.circom",
];

pub fn compile(relative: &str) -> Compiled {
    circomlib::compile(relative)
}

fn named(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

fn signal(name: &'static str, values: &[Fr]) -> (&'static str, Vec<String>) {
    (
        name,
        values
            .iter()
            .map(|value| decimal(Field::from(*value)))
            .collect(),
    )
}

/// The relation cases of a two-operand gate: every boolean pair with its
/// honest and its negated claim, every wrong claim on (1, 1), and every
/// non-boolean pair claiming the gate's polynomial, all other SDK wires
/// consistent with it.
pub fn gate_cases<const GATE: usize>() -> Vec<Case<Variables<GATE>>> {
    let gate = &GATES[GATE];
    let fixture = |a: Fr, b: Fr, out: Fr| Variables::<GATE> {
        a: a.into(),
        b: b.into(),
        out: out.into(),
    };
    let circom =
        |a: Fr, b: Fr, out: Fr| vec![signal("a", &[a]), signal("b", &[b]), signal("out", &[out])];
    let honest_of = |a: bool, b: bool| {
        let out = Fr::from(gate.output(a, b));
        fixture(Fr::from(a), Fr::from(b), out)
    };
    let mut cases = vec![];
    for pair in &BOOLEAN_PAIRS {
        let (x, y) = pair.bits();
        let (a, b, out) = (Fr::from(x), Fr::from(y), Fr::from(gate.output(x, y)));
        cases.push(Case {
            name: pair.name,
            holds: true,
            fixture: fixture(a, b, out),
            sdk_witness: SdkWitness::Assignment,
            circom: circom(a, b, out),
        });
        let flipped = Fr::one() - out;
        cases.push(Case {
            name: named(format!("{} claims the negation", pair.name)),
            holds: false,
            fixture: fixture(a, b, flipped),
            sdk_witness: SdkWitness::Tampered {
                honest: honest_of(x, y),
                wires: vec![(3, flipped)],
            },
            circom: circom(a, b, flipped),
        });
    }
    for claim in &WRONG_CLAIMS {
        let (one, out) = (Fr::one(), Fr::from(claim.field()));
        cases.push(Case {
            name: named(format!("1, 1 claims {}", claim.name)),
            holds: false,
            fixture: fixture(one, one, out),
            sdk_witness: SdkWitness::Tampered {
                honest: honest_of(true, true),
                wires: vec![(3, out)],
            },
            circom: circom(one, one, out),
        });
    }
    for pair in &NON_BOOLEAN_PAIRS {
        let (a, b) = pair.fields();
        let (a, b) = (Fr::from(a), Fr::from(b));
        let out = gate.polynomial(a, b);
        cases.push(Case {
            name: pair.name,
            holds: false,
            fixture: fixture(a, b, out),
            sdk_witness: SdkWitness::Tampered {
                honest: honest_of(false, false),
                wires: vec![(1, a), (2, b), (3, out), (4, a * b)],
            },
            circom: circom(a, b, out),
        });
    }
    cases
}

pub fn not_cases() -> Vec<Case<Not>> {
    let fixture = |a: Fr, out: Fr| Not {
        a: a.into(),
        out: out.into(),
    };
    let circom = |a: Fr, out: Fr| vec![signal("a", &[a]), signal("out", &[out])];
    let honest = |a: Fr| fixture(a, Fr::one() - a);
    let mut cases = vec![];
    for bit in &BITS {
        let a = Fr::from(bit.field());
        let out = Fr::one() - a;
        cases.push(Case {
            name: bit.name,
            holds: true,
            fixture: fixture(a, out),
            sdk_witness: SdkWitness::Assignment,
            circom: circom(a, out),
        });
        cases.push(Case {
            name: named(format!("{} claims itself", bit.name)),
            holds: false,
            fixture: fixture(a, a),
            sdk_witness: SdkWitness::Tampered {
                honest: honest(a),
                wires: vec![(2, a)],
            },
            circom: circom(a, a),
        });
    }
    for x in &NON_BOOLEAN {
        let a = Fr::from(x.field());
        cases.push(Case {
            name: x.name,
            holds: false,
            fixture: fixture(a, Fr::one() - a),
            sdk_witness: SdkWitness::Tampered {
                honest: honest(Fr::from(0u64)),
                wires: vec![(1, a), (2, Fr::one() - a)],
            },
            circom: circom(a, Fr::one() - a),
        });
    }
    cases
}

/// The relation cases of a fold of three flags: every combination with its
/// honest and its negated claim, and `deceptive`, whose sum is the one the
/// fold compares against, claiming `deceptive_out` with the equality test's
/// witnesses consistent with that sum.
pub fn fold_cases<const OP: usize>(
    deceptive: (&'static str, [&'static str; 3]),
    deceptive_out: bool,
) -> Vec<Case<Fold<OP, 3>>> {
    let op = &super::fixtures::FOLDS[OP];
    let fixture = |flags: [Fr; 3], out: Fr| Fold::<OP, 3> {
        flags: flags.map(Field::from),
        out: out.into(),
    };
    let circom = |flags: [Fr; 3], out: Fr| vec![signal("flags", &flags), signal("out", &[out])];
    let honest_of = |flags: &[bool]| {
        let out = Fr::from((op.truth)(flags));
        fixture([0, 1, 2].map(|index| Fr::from(flags[index])), out)
    };
    let mut cases = vec![];
    for (name, flags) in FLAGS.iter().filter(|(_, flags)| flags.len() == 3) {
        let values = [0, 1, 2].map(|index| Fr::from(flags[index]));
        let out = Fr::from((op.truth)(flags));
        cases.push(Case {
            name,
            holds: true,
            fixture: fixture(values, out),
            sdk_witness: SdkWitness::Assignment,
            circom: circom(values, out),
        });
        let flipped = Fr::one() - out;
        cases.push(Case {
            name: named(format!("{name} claims the negation")),
            holds: false,
            fixture: fixture(values, flipped),
            sdk_witness: SdkWitness::Tampered {
                honest: honest_of(flags),
                wires: vec![(4, flipped)],
            },
            circom: circom(values, flipped),
        });
    }
    let (name, decimals) = deceptive;
    let values = decimals.map(|decimal| Fr::from(field(decimal)));
    let out = Fr::from(deceptive_out);
    cases.push(Case {
        name,
        holds: false,
        fixture: fixture(values, out),
        sdk_witness: SdkWitness::Tampered {
            honest: honest_of(&[false, false, false]),
            wires: vec![
                (1, values[0]),
                (2, values[1]),
                (3, values[2]),
                (4, out),
                (5, Fr::from(0u64)),
                (6, Fr::one()),
            ],
        },
        circom: circom(values, out),
    });
    cases
}

pub fn select_cases() -> Vec<Case<Choose<0>>> {
    let fixture = |c: Fr, t: Fr, f: Fr, out: Fr| Choose::<0> {
        condition: c.into(),
        if_true: t.into(),
        if_false: f.into(),
        out: out.into(),
    };
    let circom = |c: Fr, t: Fr, f: Fr, out: Fr| {
        vec![
            signal("condition", &[c]),
            signal("if_true", &[t]),
            signal("if_false", &[f]),
            signal("out", &[out]),
        ]
    };
    let mut cases = vec![];
    for triple in &TRIPLES {
        let (c, t, f) = triple.fields();
        let (c, t, f) = (Fr::from(c), Fr::from(t), Fr::from(f));
        let out = Fr::from(triple.selected());
        let honest = fixture(c, t, f, out);
        cases.push(Case {
            name: triple.name,
            holds: true,
            fixture: honest,
            sdk_witness: SdkWitness::Assignment,
            circom: circom(c, t, f, out),
        });
        let flipped = Fr::one() - out;
        cases.push(Case {
            name: named(format!("{} claims the other branch", triple.name)),
            holds: false,
            fixture: fixture(c, t, f, flipped),
            sdk_witness: SdkWitness::Tampered {
                honest,
                wires: vec![(4, flipped)],
            },
            circom: circom(c, t, f, flipped),
        });
    }
    let zero = Fr::from(0u64);
    let honest = fixture(zero, zero, zero, zero);
    for x in &NON_BOOLEAN {
        let x = Fr::from(x.field());
        let one = Fr::one();
        for (name, c, t, f, out, product) in [
            ("condition", x, one, zero, x, x),
            ("if_true", one, x, zero, x, x),
            ("if_false", zero, zero, x, x, zero),
        ] {
            cases.push(Case {
                name: named(format!("{name} = {}", decimal(x.into()))),
                holds: false,
                fixture: fixture(c, t, f, out),
                sdk_witness: SdkWitness::Tampered {
                    honest,
                    wires: vec![(1, c), (2, t), (3, f), (4, out), (5, product)],
                },
                circom: circom(c, t, f, out),
            });
        }
    }
    cases
}

pub fn assert_true_if_cases() -> Vec<Case<AssertedBinary<0>>> {
    let (_, holds) = &BINARY_ASSERTS[0];
    let fixture = |a: Fr, b: Fr| AssertedBinary::<0> {
        a: a.into(),
        b: b.into(),
    };
    let circom = |a: Fr, b: Fr| vec![signal("a", &[a]), signal("b", &[b])];
    let zero = Fr::from(0u64);
    let honest = fixture(zero, zero);
    let mut cases = vec![];
    for pair in &BOOLEAN_PAIRS {
        let (a, b) = pair.fields();
        let (a, b) = (Fr::from(a), Fr::from(b));
        let holds = holds[pair.row()];
        cases.push(Case {
            name: pair.name,
            holds,
            fixture: fixture(a, b),
            sdk_witness: if holds {
                SdkWitness::Assignment
            } else {
                SdkWitness::Tampered {
                    honest,
                    wires: vec![(1, a), (2, b)],
                }
            },
            circom: circom(a, b),
        });
    }
    for x in &NON_BOOLEAN {
        let x = Fr::from(x.field());
        for (name, a, b) in [("a", x, zero), ("b", Fr::one(), x)] {
            cases.push(Case {
                name: named(format!("{name} = {}", decimal(x.into()))),
                holds: false,
                fixture: fixture(a, b),
                sdk_witness: SdkWitness::Tampered {
                    honest,
                    wires: vec![(1, a), (2, b)],
                },
                circom: circom(a, b),
            });
        }
    }
    cases
}

fn gate_equivalence<const GATE: usize>() -> (&'static str, (Size, Size)) {
    let compiled = compile(GATE_REFERENCES[GATE]);
    assert_relation_equivalent(&compiled, &gate_cases::<GATE>());
    (GATES[GATE].name, sizes::<Variables<GATE>>(&compiled))
}

fn size(constraints: usize, variables: usize) -> Size {
    Size {
        constraints,
        variables,
    }
}

#[test]
fn every_two_operand_gate_is_relation_equivalent_to_its_circom_reference() {
    let sdk = size(4, 5);
    assert_eq!(
        [
            gate_equivalence::<0>(),
            gate_equivalence::<1>(),
            gate_equivalence::<2>(),
            gate_equivalence::<3>(),
            gate_equivalence::<4>(),
            gate_equivalence::<5>(),
        ],
        [
            ("and", (sdk, size(6, 7))),
            ("or", (sdk, size(6, 7))),
            ("xor", (sdk, size(6, 7))),
            ("nand", (sdk, size(6, 7))),
            ("implies", (sdk, size(6, 7))),
            ("is_equal", (sdk, size(9, 10))),
        ]
    );
}

#[test]
fn not_is_relation_equivalent_to_circomlib_not() {
    let compiled = compile("bool/circom/not.circom");
    assert_relation_equivalent(&compiled, &not_cases());
    assert_eq!(sizes::<Not>(&compiled), (size(2, 3), size(4, 5)));
}

#[test]
fn all_of_three_flags_is_relation_equivalent_to_circomlib_multi_and() {
    let compiled = compile("bool/circom/multi_and.circom");
    assert_relation_equivalent(&compiled, &fold_cases::<ALL>(DECEPTIVE_ALL, true));
    assert_eq!(sizes::<Fold<ALL, 3>>(&compiled), (size(6, 7), size(19, 20)));
}

#[test]
fn any_of_three_flags_is_relation_equivalent_to_a_reference_over_circomlib_is_zero() {
    let compiled = compile("bool/circom/any.circom");
    assert_relation_equivalent(&compiled, &fold_cases::<ANY>(DECEPTIVE_ANY, false));
    assert_eq!(sizes::<Fold<ANY, 3>>(&compiled), (size(6, 7), size(11, 12)));
}

#[test]
fn select_is_relation_equivalent_to_circomlib_mux1() {
    let compiled = compile("bool/circom/select.circom");
    assert_relation_equivalent(&compiled, &select_cases());
    assert_eq!(sizes::<Choose<0>>(&compiled), (size(5, 6), size(12, 13)));
}

#[test]
fn assert_true_if_is_relation_equivalent_to_its_circom_reference() {
    let compiled = compile("bool/circom/assert_true_if.circom");
    assert_relation_equivalent(&compiled, &assert_true_if_cases());
    assert_eq!(
        sizes::<AssertedBinary<0>>(&compiled),
        (size(3, 3), size(3, 3))
    );
}

fn wtns_checks<const GATE: usize>(
    work: &WorkDir,
) -> (&'static str, Vec<(&'static str, [WtnsCheck; 3])>) {
    let r1cs = work.write(
        &format!("gate-{GATE}.r1cs"),
        &Variables::<GATE>::export_r1cs().expect("r1cs export"),
    );
    let gate = &GATES[GATE];
    let checked = BOOLEAN_PAIRS
        .iter()
        .enumerate()
        .map(|(index, pair)| {
            let (x, y) = pair.bits();
            let fixture = Variables::<GATE> {
                a: Field::from(x),
                b: Field::from(y),
                out: Field::from(gate.output(x, y)),
            };
            let honest = assignment(&fixture);
            let mut flipped = honest.clone();
            flipped[3] = Fr::one() - flipped[3];
            let two = Fr::from(2u64);
            let mut non_boolean = honest.clone();
            non_boolean[1] = two;
            non_boolean[3] = gate.polynomial(two, non_boolean[2]);
            non_boolean[4] = two * non_boolean[2];
            let check = |kind: &str, witness: &[Fr]| {
                let wtns = work.write(
                    &format!("gate-{GATE}-{index}-{kind}.wtns"),
                    &write_wtns(witness),
                );
                snarkjs::wtns_check(&r1cs, &wtns)
            };
            (
                pair.name,
                [
                    check("honest", &honest),
                    check("flipped", &flipped),
                    check("non-boolean", &non_boolean),
                ],
            )
        })
        .collect();
    (gate.name, checked)
}

#[test]
fn snarkjs_accepts_every_honest_gate_witness_and_rejects_a_flipped_or_non_boolean_one() {
    let work = WorkDir::new("snarkjs-bool-gates");
    let expected = || {
        BOOLEAN_PAIRS
            .iter()
            .map(|pair| {
                (
                    pair.name,
                    [
                        WtnsCheck::Accepted,
                        WtnsCheck::Rejected,
                        WtnsCheck::Rejected,
                    ],
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        [
            wtns_checks::<0>(&work),
            wtns_checks::<1>(&work),
            wtns_checks::<2>(&work),
            wtns_checks::<3>(&work),
            wtns_checks::<4>(&work),
            wtns_checks::<5>(&work),
        ],
        GATES.map(|gate| (gate.name, expected()))
    );
}

#[test]
fn snarkjs_accepts_exactly_the_witnesses_on_which_an_assertion_holds() {
    let work = WorkDir::new("snarkjs-bool-assertions");
    let check = |name: &str, r1cs: &[u8], witness: &[Fr]| {
        let r1cs = work.write(&format!("{name}.r1cs"), r1cs);
        let wtns = work.write(&format!("{name}.wtns"), &write_wtns(witness));
        snarkjs::wtns_check(&r1cs, &wtns)
    };
    let verdict = |holds: bool| {
        if holds {
            WtnsCheck::Accepted
        } else {
            WtnsCheck::Rejected
        }
    };
    let one = Fr::one();
    let unary = [
        AssertedUnary::<0>::export_r1cs().expect("r1cs export"),
        AssertedUnary::<1>::export_r1cs().expect("r1cs export"),
    ];
    let assert_true_if = AssertedBinary::<0>::export_r1cs().expect("r1cs export");
    assert_eq!(
        (
            UNARY_ASSERTS
                .iter()
                .zip(&unary)
                .map(|((op, _), r1cs)| {
                    let checked = BITS.map(|bit| {
                        let name = format!("{}-{}", op.name, bit.name);
                        check(&name, r1cs, &[one, bit.field().into()])
                    });
                    (op.name, checked)
                })
                .collect::<Vec<_>>(),
            BOOLEAN_PAIRS.map(|pair| {
                let (a, b) = pair.fields();
                let name = format!("assert-true-if-{}", pair.row());
                (
                    pair.name,
                    check(&name, &assert_true_if, &[one, a.into(), b.into()]),
                )
            }),
        ),
        (
            UNARY_ASSERTS
                .iter()
                .map(|(op, holds)| (op.name, holds.map(verdict)))
                .collect::<Vec<_>>(),
            BOOLEAN_PAIRS.map(|pair| (pair.name, verdict(BINARY_ASSERTS[0].1[pair.row()]))),
        )
    );
}

#[test]
fn snarkjs_proves_and_verifies_select_and_a_fold_of_three_flags() {
    let one = Field::from(1u64);
    let zero = Field::from(0u64);
    let prove = |name: &str, r1cs: Vec<u8>, wtns: Vec<u8>| {
        let work = WorkDir::new(&format!("snarkjs-bool-groth16-{name}"));
        let header = read_r1cs(&r1cs).header;
        let r1cs = work.write("sdk.r1cs", &r1cs);
        let wtns = work.write("sdk.wtns", &wtns);
        (
            header.constraints,
            snarkjs::ptau_power(&header),
            snarkjs::groth16(&work, &r1cs, &wtns),
        )
    };
    assert_eq!(
        (
            prove(
                "select",
                Choose::<0>::export_r1cs().expect("r1cs export"),
                Choose::<0> {
                    condition: one,
                    if_true: zero,
                    if_false: one,
                    out: zero,
                }
                .export_assignment()
                .expect("assignment"),
            ),
            prove(
                "all",
                Fold::<ALL, 3>::export_r1cs().expect("r1cs export"),
                Fold::<ALL, 3> {
                    flags: [one, zero, one],
                    out: zero,
                }
                .export_assignment()
                .expect("assignment"),
            ),
        ),
        ((5, 4, (true, json!([]))), (6, 4, (true, json!([]))))
    );
}
