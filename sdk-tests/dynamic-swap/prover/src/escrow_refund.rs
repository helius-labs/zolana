use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

#[derive(Debug, Clone)]
pub struct EscrowRefundProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub execution_price: u64,
    pub quote_version: u64,
    pub order_in_hash: [u8; 32],
    pub max_price: u64,
    pub recipient_owner_hash: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    pub order_in: ProofInputUtxo,
    pub recipient_out: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl EscrowRefundProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let mut map = HashMap::new();
        for (name, value) in [
            (
                "Public_PublicInputHash",
                bytes_to_decimal_string(&self.public_input_hash),
            ),
            (
                "Public_PrivateTxHash",
                bytes_to_decimal_string(&self.private_tx_hash),
            ),
            ("Public_ExecutionPrice", self.execution_price.to_string()),
            ("Public_QuoteVersion", self.quote_version.to_string()),
            (
                "Public_OrderInHash",
                bytes_to_decimal_string(&self.order_in_hash),
            ),
            ("MaxPrice", self.max_price.to_string()),
            (
                "RecipientOwnerHash",
                bytes_to_decimal_string(&self.recipient_owner_hash),
            ),
            ("CreatedAt", self.created_at.to_string()),
            ("ExpiresAt", self.expires_at.to_string()),
            (
                "ExternalDataHash",
                bytes_to_decimal_string(&self.external_data_hash),
            ),
        ] {
            map.insert(name.to_string(), vec![value]);
        }
        for (key, value) in utxo_witness_entries(&self.order_in, "OrderIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.recipient_out, "RecipientOut"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::EscrowRefund, &self.witness())?)
    }
}
