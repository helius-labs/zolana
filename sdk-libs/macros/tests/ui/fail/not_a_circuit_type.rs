use zolana_program::{
    conversion::{Allocator, ProofInput},
    CircuitError,
};

struct Raw {
    value: u64,
}

impl ProofInput for Raw {
    type Circuit = u64;

    fn instantiate(&self, _allocator: &Allocator) -> Result<u64, CircuitError> {
        Ok(self.value)
    }
}

fn main() {}
