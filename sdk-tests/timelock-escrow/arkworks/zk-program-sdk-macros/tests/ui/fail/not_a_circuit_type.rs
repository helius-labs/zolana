use zk_program_sdk::{
    conversion::{Allocator, ProofInput},
    RelationError,
};

struct Raw {
    value: u64,
}

impl ProofInput for Raw {
    type Circuit = u64;

    fn instantiate(&self, _allocator: &Allocator) -> Result<u64, RelationError> {
        Ok(self.value)
    }
}

fn main() {}
