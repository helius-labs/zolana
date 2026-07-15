use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    CircuitId, OrderTermsFieldElements, UtxoFieldElements,
};

pub const DESTINATION_BLINDING_DOMAIN: u64 = 0x46494C4C44455256;

#[derive(Debug, Clone)]
pub struct FillProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsFieldElements,
    pub escrow: UtxoFieldElements,
    pub taker_in: UtxoFieldElements,
    pub source_output: UtxoFieldElements,
    pub destination_output: UtxoFieldElements,
    pub external_data_hash: [u8; 32],
}

impl FillProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 3] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("Core_ExternalDataHash", self.external_data_hash),
        ];
        let mut map = HashMap::new();
        for (key, value) in scalars.iter() {
            map.insert(key.to_string(), vec![bytes_to_decimal_string(value)]);
        }
        for (key, value) in self
            .order
            .witness_entries("Core_Order")
            .into_iter()
            .chain(self.escrow.witness_entries("Core_Escrow"))
            .chain(self.taker_in.witness_entries("Core_TakerIn"))
            .chain(self.source_output.witness_entries("Core_SourceOutput"))
            .chain(
                self.destination_output
                    .witness_entries("Core_DestinationOutput"),
            )
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Fill, &self.witness())?)
    }
}
