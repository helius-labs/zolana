#![cfg(feature = "external-tools")]

use std::time::Duration;

use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::ZkCircuit;

use super::{fixture, Product, VECTORS};
use crate::harness::{
    circom,
    equivalence::{assert_relation_equivalent, picus_verdicts, Case, SdkWitness},
    field::decimal,
    fixture::{assignment, export},
    iden3::write_wtns,
    normalize::constraints,
    picus::Verdict,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

#[test]
fn circom_has_the_same_product_relation_for_honest_and_wrong_boundary_claims() {
    let circom = circom::compile("ops/product/product.circom");
    assert_eq!(
        constraints(&super::exported::<Product>()),
        constraints(&circom.read_r1cs())
    );
    for vector in VECTORS {
        let honest = fixture(vector);
        for holds in [true, false] {
            let input = Product {
                product: (Fr::from(honest.product) + Fr::from(u64::from(!holds))).into(),
                ..honest
            };
            assert_relation_equivalent(
                &circom,
                &[Case {
                    name: "product",
                    holds,
                    fixture: input,
                    sdk_witness: SdkWitness::Tampered {
                        honest,
                        wires: vec![(3, input.product.into())],
                    },
                    circom: vec![
                        ("left", vec![decimal(input.left)]),
                        ("right", vec![decimal(input.right)]),
                        ("product", vec![decimal(input.product)]),
                    ],
                }],
            );
        }
    }
}

#[test]
fn picus_proves_the_claimed_product_fixed_by_its_factors() {
    let circom = circom::compile("ops/product/product.circom");
    assert_eq!(
        picus_verdicts::<Product>(
            &WorkDir::new("product-picus"),
            "product",
            &[3],
            &circom,
            &[circom.wire("main.product")],
            Duration::from_secs(60)
        ),
        (Verdict::Safe, Verdict::Safe)
    );
}

#[test]
fn snarkjs_checks_the_relation_rejects_a_wrong_product_and_verifies_a_proof() {
    let work = WorkDir::new("product-snarkjs");
    let input = fixture(("2", "3", "6"));
    let r1cs = work.write("product.r1cs", &export::<Product>());
    let wtns = work.write(
        "honest.wtns",
        &input.export_assignment().expect("assignment"),
    );
    let mut wrong = assignment(&input);
    *wrong.get_mut(3).expect("product wire") += Fr::one();
    let tampered = work.write("tampered.wtns", &write_wtns(&wrong));
    assert_eq!(snarkjs::wtns_check(&r1cs, &wtns), WtnsCheck::Accepted);
    assert_eq!(snarkjs::wtns_check(&r1cs, &tampered), WtnsCheck::Rejected);
    assert_eq!(
        snarkjs::groth16(&work, &r1cs, &wtns),
        (true, serde_json::json!([]))
    );
}
