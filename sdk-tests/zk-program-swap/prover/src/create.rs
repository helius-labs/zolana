use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    CircuitId, OrderTermsFieldElements, UtxoFieldElements,
};

#[derive(Debug, Clone)]
pub struct CreateProofInputs {
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsFieldElements,
    pub escrow: UtxoFieldElements,
    pub change: UtxoFieldElements,
    pub source_input_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl CreateProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 3] = [
            ("PrivateTxHash", self.private_tx_hash),
            ("SourceInputHash", self.source_input_hash),
            ("ExternalDataHash", self.external_data_hash),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in self
            .order
            .witness_entries("Order")
            .into_iter()
            .chain(self.escrow.witness_entries("Escrow"))
            .chain(self.change.witness_entries("Change"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Create, &self.witness())?)
    }
}
