use zk_program_sdk::{
    circuit::{CheckedTransaction, Circuit, CircuitType},
    CircuitError,
};

struct HandWritten;

impl CircuitType for HandWritten {}

impl Circuit for HandWritten {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        unimplemented!()
    }
}

fn main() {}
