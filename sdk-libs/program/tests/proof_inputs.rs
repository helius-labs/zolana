#![cfg(feature = "client")]

use zolana_program::{
    circuit::Assert,
    circuit::{CircuitType, Constraints, Uint},
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, ProofInputs, ZkCircuit,
};

struct PrivateValue(u64);
struct PrivateValueCircuit(Uint<64>);

impl CircuitType for PrivateValueCircuit {}

impl Constraints for PrivateValueCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
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
