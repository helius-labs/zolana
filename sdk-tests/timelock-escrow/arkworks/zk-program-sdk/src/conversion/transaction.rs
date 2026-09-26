use super::{Allocator, Placeholder, ProofInput};
use crate::{circuit, RelationError, TxContext};

impl ProofInput for TxContext {
    type Circuit = circuit::TxContext;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::TxContext, RelationError> {
        Ok(circuit::TxContext {
            blinding_seed: self.blinding_seed.instantiate(allocator)?,
            output_tree_id: self.output_tree_id.unwrap_or(0).instantiate(allocator)?,
            uses_output_tree_id: self.output_tree_id.is_some().instantiate(allocator)?,
        })
    }
}

impl Placeholder for TxContext {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            blinding_seed: [0u8; 32],
            output_tree_id: Some(0),
        })
    }
}
