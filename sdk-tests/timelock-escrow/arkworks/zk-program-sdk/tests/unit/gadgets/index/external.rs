#![cfg(feature = "external-tools")]
use super::{
    fixtures::{decoded, selected, OneHot, SelectIndex},
    vectors::{invalid_indices, items},
};
use crate::harness::{
    circom::Compiled,
    circomlib,
    equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
    field::{decimal, field},
    fixture::{assignment, with_wires, Size},
    iden3::write_wtns,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};
use serde_json::json;
use zk_program_sdk::{circuit::Field, ZkCircuit};
pub fn compiled(name: &str) -> Compiled {
    circomlib::compile(&format!("gadgets/index/{name}.circom"))
}
fn flags_input(fixture: &OneHot<3>) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("index", vec![decimal(fixture.index)]),
        ("flags", fixture.flags.map(decimal).to_vec()),
    ]
}
fn select_input(fixture: &SelectIndex<3>) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("items", fixture.items.map(decimal).to_vec()),
        ("index", vec![decimal(fixture.index)]),
        ("selected", vec![decimal(fixture.selected)]),
    ]
}

#[test]
fn circomlib_decoder_accepts_exactly_the_sdk_indices_and_flags() {
    let mut cases = Vec::new();
    for index in 0..3 {
        let honest = decoded::<3>(index);
        cases.push(Case {
            name: "valid index",
            holds: true,
            fixture: honest,
            sdk_witness: SdkWitness::Assignment,
            circom: flags_input(&honest),
        });
        for position in 0..3 {
            let mut wrong = honest;
            let flag = wrong.flags.get_mut(position).expect("flag");
            *flag = *flag + field("1");
            cases.push(Case {
                name: "changed flag",
                holds: false,
                fixture: wrong,
                sdk_witness: SdkWitness::Tampered {
                    honest,
                    wires: vec![(
                        position + 2,
                        (*wrong.flags.get(position).expect("flag")).into(),
                    )],
                },
                circom: flags_input(&wrong),
            });
        }
    }
    for index in invalid_indices() {
        let wrong = OneHot {
            index,
            flags: [field("0"); 3],
        };
        cases.push(Case {
            name: "out of bounds",
            holds: false,
            fixture: wrong,
            sdk_witness: SdkWitness::Explicit(super::r1cs::out_of_bounds_one_hot(index)),
            circom: flags_input(&wrong),
        });
    }
    assert_relation_equivalent(&compiled("one_hot"), &cases);
}

#[test]
fn circomlib_multiplexer_accepts_exactly_the_sdk_indices_and_selections() {
    let mut cases = Vec::new();
    for items in items() {
        for index in 0..3 {
            let honest = selected(items, index);
            cases.push(Case {
                name: "valid selection",
                holds: true,
                fixture: honest,
                sdk_witness: SdkWitness::Assignment,
                circom: select_input(&honest),
            });
            let mut wrong = honest;
            wrong.selected = wrong.selected + field("1");
            cases.push(Case {
                name: "changed output",
                holds: false,
                fixture: wrong,
                sdk_witness: SdkWitness::Tampered {
                    honest,
                    wires: vec![(5, wrong.selected.into())],
                },
                circom: select_input(&wrong),
            });
        }
    }
    for index in invalid_indices() {
        let honest = selected([Field::from(7u64); 3], 0);
        let wrong = SelectIndex { index, ..honest };
        cases.push(Case {
            name: "out of bounds",
            holds: false,
            fixture: wrong,
            sdk_witness: SdkWitness::Explicit(super::r1cs::out_of_bounds_selection(index)),
            circom: select_input(&wrong),
        });
    }
    assert_relation_equivalent(&compiled("select_index"), &cases);
}

#[test]
fn indexing_sizes_are_pinned_against_circomlib() {
    assert_eq!(
        sizes::<OneHot<3>>(&compiled("one_hot")),
        (
            Size {
                constraints: 10,
                variables: 11
            },
            Size {
                constraints: 10,
                variables: 10
            }
        )
    );
    assert_eq!(
        sizes::<SelectIndex<3>>(&compiled("select_index")),
        (
            Size {
                constraints: 10,
                variables: 14
            },
            Size {
                constraints: 23,
                variables: 26
            }
        )
    );
}

#[test]
fn snarkjs_checks_honest_and_tampered_indices_and_proves_both_operations() {
    fn check<F: ZkCircuit>(name: &str, fixture: F, wire: usize) {
        let work = WorkDir::new(name);
        let r1cs = work.write("sdk.r1cs", &F::export_r1cs().expect("r1cs"));
        let witness = assignment(&fixture);
        let changed = *witness.get(wire).expect("wire") + ark_bn254::Fr::from(1u64);
        let honest = work.write("honest.wtns", &write_wtns(&witness));
        let wrong = work.write(
            "wrong.wtns",
            &write_wtns(&with_wires(witness, &[(wire, changed)])),
        );
        assert_eq!(
            (
                snarkjs::wtns_check(&r1cs, &honest),
                snarkjs::wtns_check(&r1cs, &wrong)
            ),
            (WtnsCheck::Accepted, WtnsCheck::Rejected)
        );
        assert_eq!(snarkjs::groth16(&work, &r1cs, &honest), (true, json!([])));
    }
    check("one-hot-snarkjs", decoded::<3>(1), 3);
    check("select-index-snarkjs", selected(items()[0], 2), 5);
}
