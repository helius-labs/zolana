#![cfg(feature = "client")]

use zolana_program::{
    circuit::Assert,
    circuit::{Circuit, CircuitType, Uint},
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, ProofInputs, ZkCircuit,
};

struct PrivateValue(u64);
struct PrivateValueCircuit(Uint<64>);

impl CircuitType for PrivateValueCircuit {}

impl Circuit for PrivateValueCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.0
            .assert_equal(&Uint::<64>::constant(7)?, "the private value must be seven")
    }
}

impl ProofInput for PrivateValue {
    type Circuit = PrivateValueCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<Self::Circuit, CircuitError> {
        Ok(PrivateValueCircuit(self.0.instantiate(allocator)?))
    }
}

impl Placeholder for PrivateValue {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self(7))
    }
}

#[test]
fn a_private_variable_cannot_be_read_as_a_public_hash() {
    let assignment = PrivateValue(7).proof_inputs().unwrap();
    assert!(assignment.public_hash().is_err());
    let bytes = assignment.to_bytes().unwrap();
    let imported = ProofInputs::from_bytes(&bytes).unwrap();
    assert!(imported.public_hash().is_err());
    assert_eq!(imported.to_bytes().unwrap(), bytes);
}

#[cfg(feature = "setup")]
#[test]
fn a_standalone_circuits_r1cs_and_assignment_digests_are_pinned() {
    use sha2::{Digest, Sha256};
    let actual = [
        PrivateValue::export_r1cs().unwrap(),
        PrivateValue::export_picus_r1cs().unwrap(),
        PrivateValue(7).export_assignment().unwrap(),
    ]
    .map(|bytes| hex::encode(Sha256::digest(bytes)));
    assert_eq!(actual, STANDALONE_DIGESTS);
}

// A `()` circuit has no public input; any change to its rows, variables or
// assignment order moves these digests. Columns: R1CS, Picus R1CS, WTNS.
#[cfg(feature = "setup")]
const STANDALONE_DIGESTS: [&str; 3] = [
    "154e9f6ccbcc2165641d92e2ff25e8e81ac98d1c066098ba4b1a5ffc9a548f0d",
    "7902da832fd2528d54739231a858d71c8c54053091a151fba8caf07bffd3f526",
    "e2e56832398ba54c87c279a0aad21f832062443d5742b9f458df30abee25b6b9",
];
