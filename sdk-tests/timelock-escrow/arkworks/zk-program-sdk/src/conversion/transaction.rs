use super::{Allocator, ProofInput};
use crate::{circuit, RelationError, TxContext};

impl ProofInput for TxContext {
    type Circuit = circuit::TxContext;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::TxContext, RelationError> {
        Ok(circuit::TxContext {
            first_nullifier: self.first_nullifier.instantiate(allocator)?,
            blinding_seed: self.blinding_seed.instantiate(allocator)?,
            output_tree_id: self.output_tree_id.instantiate(allocator)?,
            sender: self.sender.instantiate(allocator)?,
        })
    }
}
