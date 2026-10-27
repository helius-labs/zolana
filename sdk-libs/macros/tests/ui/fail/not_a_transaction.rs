use spr_program::{
    circuit::Circuit,
    conversion::ProofInput,
    CircuitError, ZkCircuit, ZkProgramCircuit,
};

#[derive(Clone, ProofInput)]
struct Standalone;

impl Circuit for StandaloneCircuit {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        Ok(())
    }
}

fn require_circuit<P: ZkCircuit>() {}
fn require_program<P: ZkProgramCircuit>() {}

fn main() {
    require_circuit::<Standalone>();
    require_program::<Standalone>();
}
