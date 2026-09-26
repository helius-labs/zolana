use ark_bn254::Fr;
use ark_ff::One;
use sha2::{Digest, Sha256};
use timelock_escrow_arkworks::{Escrow, Withdraw};
use zk_program_sdk::ZkProgram;

mod iden3;
mod programs;
mod shared;

use iden3::{read_r1cs, read_wtns, scalar_prime, R1csHeader};

const ESCROW_R1CS_SHA256: &str = "5fc00ca721efa967fee74cb743f603b8b2b19e13d3eb12c1edd30f4a092f56f5";
const WITHDRAW_R1CS_SHA256: &str =
    "2142132634306b588460290f2347889e458a8988f970b18520ac4f9fc830dbd0";

fn exported_r1cs_matches_the_circuit<P: ZkProgram>(program: &P) {
    let r1cs = read_r1cs(&P::export_r1cs().expect("r1cs export"));
    let witness = read_wtns(&program.export_assignment().expect("assignment export"));
    let variables = witness.len();
    let mut tampered = witness.clone();
    if let Some(last) = tampered.last_mut() {
        *last += Fr::one();
    }

    assert_eq!(
        (
            &r1cs.header,
            witness.first().copied(),
            r1cs.first_unsatisfied(&witness),
            r1cs.first_unsatisfied(&tampered).is_some(),
        ),
        (
            &R1csHeader {
                field_size: 32,
                prime: scalar_prime(),
                variables,
                public_outputs: 0,
                public_inputs: 1,
                private_inputs: variables - 2,
                labels: u64::try_from(variables).expect("label count"),
                constraints: program.check_constraints().expect("constraint count"),
            },
            Some(Fr::one()),
            None,
            true,
        )
    );
}

#[test]
fn the_escrow_r1cs_holds_its_constraints_in_variable_order() {
    exported_r1cs_matches_the_circuit(&programs::escrow());
}

#[test]
fn the_withdraw_r1cs_holds_its_constraints_in_variable_order() {
    exported_r1cs_matches_the_circuit(&programs::withdraw());
}

#[test]
fn the_exported_r1cs_files_are_pinned() {
    let digest = |r1cs: Vec<u8>| hex::encode(Sha256::digest(r1cs));

    assert_eq!(
        (
            digest(Escrow::export_r1cs().expect("escrow r1cs")),
            digest(Withdraw::export_r1cs().expect("withdraw r1cs")),
        ),
        (
            ESCROW_R1CS_SHA256.to_string(),
            WITHDRAW_R1CS_SHA256.to_string(),
        )
    );
}
