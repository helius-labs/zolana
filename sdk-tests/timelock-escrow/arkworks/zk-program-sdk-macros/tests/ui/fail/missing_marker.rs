use zk_program_sdk::{
    circuit::{CheckedTransaction, Circuit, CircuitType},
    RelationError,
};

struct HandWritten;

impl CircuitType for HandWritten {}

impl Circuit for HandWritten {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        unimplemented!()
    }
}

fn main() {}
