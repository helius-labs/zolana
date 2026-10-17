use zolana_program::{
    circuit::Circuit,
    conversion::ProofInput,
    CircuitError, ZkCircuit, ZkProgram,
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
fn require_program<P: ZkProgram>() {}

fn main() {
    require_circuit::<Standalone>();
    require_program::<Standalone>();
}
