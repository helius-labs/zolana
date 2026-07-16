use std::collections::HashMap;

use zolana_transaction::ProofInputUtxo;

use crate::{
    bytes_to_decimal_string, ffi,
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    CircuitId, OrderTermsProofInput,
};

#[derive(Debug, Clone)]
pub struct CancelProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub order: OrderTermsProofInput,
    pub maker_owner_pk_field: [u8; 32],
    pub maker_nullifier_pk: [u8; 32],
    pub order_utxo: ProofInputUtxo,
    pub source_output: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl CancelProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let scalars: [(&str, [u8; 32]); 5] = [
            ("Public_PublicInputHash", self.public_input_hash),
            ("Public_PrivateTxHash", self.private_tx_hash),
            ("MakerOwnerPkField", self.maker_owner_pk_field),
            ("MakerNullifierPk", self.maker_nullifier_pk),
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
            .chain(utxo_witness_entries(&self.order_utxo, "OrderUtxo"))
            .chain(utxo_witness_entries(&self.source_output, "SourceOutput"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::Cancel, &self.witness())?)
    }
}
