use std::collections::HashMap;

use zolana_transaction::ProofInputUtxo;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    CircuitId, OrderTermsProofInput,
};

pub const DESTINATION_BLINDING_DOMAIN: u64 = 0x46494C4C44455256;

#[derive(Debug, Clone)]
pub struct TakeProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsProofInput,
    pub order_utxo: ProofInputUtxo,
    pub taker_in: ProofInputUtxo,
    pub source_output: ProofInputUtxo,
    pub destination_output: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl TakeProofInputs {
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
            .chain(utxo_witness_entries(&self.order_utxo, "Core_OrderUtxo"))
            .chain(utxo_witness_entries(&self.taker_in, "Core_TakerIn"))
            .chain(utxo_witness_entries(
                &self.source_output,
                "Core_SourceOutput",
            ))
            .chain(utxo_witness_entries(
                &self.destination_output,
                "Core_DestinationOutput",
            ))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Take, &self.witness())?)
    }
}
