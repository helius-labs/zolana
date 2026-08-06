use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

#[derive(Debug, Clone)]
pub struct EscrowSettleProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub execution_price: u64,
    pub quote_version: u64,
    pub order_in_hash: [u8; 32],
    pub pool_in_hash: [u8; 32],
    pub authority_owner_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub remaining_reserved_liability: u64,
    pub slot_value: u64,
    pub available_slots: u64,
    pub refresh_capacity: bool,
    pub order_amount: u64,
    pub max_price: u64,
    pub recipient_owner_hash: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    pub order_in: ProofInputUtxo,
    pub pool_in: ProofInputUtxo,
    pub recipient_out: ProofInputUtxo,
    pub pool_out: ProofInputUtxo,
    pub authority_out: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl EscrowSettleProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let mut map = HashMap::new();
        let fields = [
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
            (
                "Public_PoolInHash",
                bytes_to_decimal_string(&self.pool_in_hash),
            ),
            (
                "Public_AuthorityOwnerHash",
                bytes_to_decimal_string(&self.authority_owner_hash),
            ),
            (
                "Public_DestinationAsset",
                bytes_to_decimal_string(&self.destination_asset),
            ),
            (
                "Public_RemainingReservedLiability",
                self.remaining_reserved_liability.to_string(),
            ),
            ("Public_SlotValue", self.slot_value.to_string()),
            ("Public_AvailableSlots", self.available_slots.to_string()),
            (
                "Public_RefreshCapacity",
                u8::from(self.refresh_capacity).to_string(),
            ),
            ("OrderAmount", self.order_amount.to_string()),
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
        ];
        for (name, value) in fields {
            map.insert(name.to_string(), vec![value]);
        }
        for (key, value) in utxo_witness_entries(&self.order_in, "OrderIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.pool_in, "PoolIn"))
            .chain(utxo_witness_entries(&self.recipient_out, "RecipientOut"))
            .chain(utxo_witness_entries(&self.pool_out, "PoolOut"))
            .chain(utxo_witness_entries(&self.authority_out, "AuthorityOut"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::EscrowSettle, &self.witness())?)
    }
}
