#![cfg(all(feature = "client", feature = "setup"))]

extern crate zolana_zk_dsl as zolana_program;

use zolana_hasher::primitives::pack_be;
use zolana_program::{
    circuit::{Assert, Circuit, Public, PublicInputs, PublicValue},
    conversion::ProofInput,
    Bytes, CircuitError, Groth16Prover, PublicFieldKind, PublicInputLayout, ZkCircuit,
};

const RULE: &str = "the secret squares to the amount";

/// Regular public inputs covering every kind: one input each for the integer,
/// the bool and the field value, two packed chunks for 32 bytes, and one per
/// array item.
#[derive(Clone, Copy, Debug, PublicInputs)]
struct Statement {
    amount: u64,
    paid: bool,
    root: [u8; 32],
    destination: Bytes<32>,
    limits: [u16; 2],
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct Claim {
    secret: u64,
    statement: Statement,
}

impl Circuit for ClaimCircuit {
    type Output = Public<StatementCircuit>;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let square = self.secret.var().times(&self.secret.var());
        square.assert_equal(&self.statement.amount.var(), RULE)?;
        Ok(Public(self.statement.clone()))
    }
}

fn claim() -> Claim {
    let root = integer(9);
    let mut destination = [0u8; 32];
    for (byte, value) in destination.iter_mut().zip(1u8..) {
        *byte = value;
    }
    Claim {
        secret: 12,
        statement: Statement {
            amount: 144,
            paid: true,
            root,
            destination: Bytes(destination),
            limits: [3, 400],
        },
    }
}

/// A right-aligned big-endian integer, the encoding of an integer public input.
fn integer(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (target, source) in bytes.iter_mut().rev().zip(value.to_be_bytes().iter().rev()) {
        *target = *source;
    }
    bytes
}

/// The public inputs computed without the circuit, as a verifier encodes them.
fn native_public_inputs(statement: &Statement) -> Vec<[u8; 32]> {
    let mut inputs = vec![
        integer(statement.amount),
        integer(u64::from(statement.paid)),
        statement.root,
    ];
    inputs.extend(pack_be::<32, 2>(&statement.destination.0));
    inputs.extend(statement.limits.map(|limit| integer(u64::from(limit))));
    inputs
}

#[test]
fn the_layout_lists_every_field_with_its_public_input_count() {
    let layout = Statement::layout();
    assert_eq!(
        layout,
        vec![
            ("amount", PublicFieldKind::Integer { bits: 64 }),
            ("paid", PublicFieldKind::Bool),
            ("root", PublicFieldKind::Hash),
            ("destination", PublicFieldKind::Bytes { len: 32 }),
            (
                "limits",
                PublicFieldKind::Array {
                    len: 2,
                    item: Box::new(PublicFieldKind::Integer { bits: 16 }),
                }
            ),
        ]
    );
    let counted: usize = layout.iter().map(|(_, kind)| kind.public_inputs()).sum();
    assert_eq!((counted, StatementCircuit::PUBLIC_INPUTS), (7, 7));
}

#[test]
fn the_circuit_binds_the_native_encoding_of_its_public_inputs() {
    let claim = claim();
    assert_eq!(
        claim.proof_inputs().unwrap().public_inputs().unwrap(),
        native_public_inputs(&claim.statement)
    );
}

#[test]
fn a_proof_verifies_only_under_its_own_public_inputs() {
    let claim = claim();
    let prover = Groth16Prover::<Claim>::new_with_test_setup().unwrap();
    let mut result = prover.prove(&claim).unwrap();
    assert_eq!(result.public_inputs, native_public_inputs(&claim.statement));
    prover.verify(&result).unwrap();
    // The second packed chunk of the destination holds its last byte.
    let last = result.public_inputs.get_mut(4).unwrap();
    *last = integer(1);
    assert!(prover.verify(&result).is_err());
}

#[cfg(feature = "verifier")]
#[test]
fn the_on_chain_verifier_accepts_the_proof_with_its_public_inputs() {
    use zolana_program::verifier::{
        boolean, groth16_solana::groth16::Groth16Verifyingkey, integer, pack_be, verify_groth16,
        VerifyError,
    };

    let claim = claim();
    let prover = Groth16Prover::<Claim>::new_with_test_setup().unwrap();
    let proof = prover.prove(&claim).unwrap().compressed().unwrap();
    let verifying_key = Groth16Verifyingkey::from(prover.keys().verifying_key());
    let statement = claim.statement;
    let [destination_head, destination_tail] = pack_be::<32, 2>(&statement.destination.0);
    let [low, high] = statement.limits.map(|limit| integer(u128::from(limit)));
    let mut public_inputs = [
        integer(u128::from(statement.amount)),
        boolean(statement.paid),
        statement.root,
        destination_head,
        destination_tail,
        low,
        high,
    ];
    assert_eq!(
        verify_groth16(&proof, &public_inputs, &verifying_key),
        Ok(())
    );
    public_inputs.swap(5, 6);
    assert_eq!(
        verify_groth16(&proof, &public_inputs, &verifying_key),
        Err(VerifyError::Proof)
    );
}

#[test]
fn proof_inputs_breaking_a_rule_are_refused() {
    let mut claim = claim();
    claim.secret = 11;
    assert!(claim.check_constraints().is_err());
}

/// Pins the R1CS of a `Public` output: the public inputs are variables 1..=7,
/// allocated before any private input. A changed digest changes the proving
/// key of every circuit with regular public inputs.
#[test]
fn a_public_output_keeps_its_r1cs() {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(Claim::export_r1cs().unwrap()));
    assert_eq!(digest, PUBLIC_OUTPUT_DIGEST);
}

const PUBLIC_OUTPUT_DIGEST: &str =
    "03fffb15e009e11c82ece15e5f79fefe080cade484172bdb9b6b7bd10b38c4f0";

fn rustfmt(source: &str) -> String {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run rustfmt");
    child
        .stdin
        .take()
        .expect("rustfmt stdin")
        .write_all(source.as_bytes())
        .expect("write to rustfmt");
    let output = child.wait_with_output().expect("wait for rustfmt");
    assert!(
        output.status.success(),
        "rustfmt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("rustfmt writes UTF-8")
}

/// The verifier module encodes every kind in the order the circuit binds it.
#[test]
fn the_verifier_module_encodes_every_field_kind() {
    use zolana_program::__private::render_verifier;

    assert_eq!(
        rustfmt(&render_verifier("claim", &Statement::layout())),
        include_str!("fixtures/claim_verifier.rs")
    );
}
