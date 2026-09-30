#![cfg(feature = "external-tools")]
use super::{
    fixtures::{is_in_fixture, AssertIn, IsIn},
    vectors::VECTORS,
};
use crate::harness::{
    circom::Compiled,
    circomlib,
    equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
    field::decimal,
    fixture::{assignment, with_wires, Size},
    iden3::write_wtns,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};
use serde_json::json;
use zolana_program::{circuit::Field, ZkCircuit};

pub fn compiled(name: &str) -> Compiled {
    circomlib::compile(&format!("gadgets/membership/{name}.circom"))
}
fn inputs(value: Field, set: &[Field], member: Option<Field>) -> Vec<(&'static str, Vec<String>)> {
    let mut result = vec![
        ("value", vec![decimal(value)]),
        ("set", set.iter().copied().map(decimal).collect()),
    ];
    if let Some(member) = member {
        result.push(("member", vec![decimal(member)]));
    }
    result
}

#[test]
fn circomlib_membership_accepts_exactly_the_sdk_flags() {
    let cases: Vec<_> = VECTORS
        .iter()
        .flat_map(|vector| {
            [vector.member, !vector.member].map(|member| Case {
                name: vector.name,
                holds: member == vector.member,
                fixture: is_in_fixture(vector.value(), vector.set(), member),
                sdk_witness: SdkWitness::Tampered {
                    honest: vector.is_in(),
                    wires: vec![(5, Field::from(member).into())],
                },
                circom: inputs(vector.value(), &vector.set(), Some(Field::from(member))),
            })
        })
        .collect();
    assert_relation_equivalent(&compiled("membership"), &cases);
}

#[test]
fn the_circom_product_accepts_exactly_the_sdk_members() {
    let cases: Vec<_> = VECTORS
        .iter()
        .map(|vector| Case {
            name: vector.name,
            holds: vector.member,
            fixture: vector.assert_in(),
            sdk_witness: if vector.member {
                SdkWitness::Assignment
            } else {
                SdkWitness::Explicit(super::r1cs::outsider_witness(&vector.assert_in()))
            },
            circom: inputs(vector.value(), &vector.set(), None),
        })
        .collect();
    assert_relation_equivalent(&compiled("assert_in"), &cases);
}

#[test]
fn membership_and_assertion_sizes_are_pinned_against_circom() {
    assert_eq!(
        sizes::<IsIn<3>>(&compiled("membership")),
        (
            Size {
                constraints: 5,
                variables: 10
            },
            Size {
                constraints: 23,
                variables: 28
            }
        )
    );
    assert_eq!(
        sizes::<AssertIn<3>>(&compiled("assert_in")),
        (
            Size {
                constraints: 3,
                variables: 7
            },
            Size {
                constraints: 3,
                variables: 7
            }
        )
    );
}

#[test]
fn snarkjs_checks_honest_and_tampered_membership_and_proves_both_operations() {
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
    check("membership-snarkjs", VECTORS[0].is_in(), 5);
    check("assert-in-snarkjs", VECTORS[0].assert_in(), 1);
}
