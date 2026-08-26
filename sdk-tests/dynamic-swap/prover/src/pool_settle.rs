use std::collections::HashMap;

use crate::{
    bytes_to_decimal_string,
    ffi::{self, CircuitId},
    proof::{negate_and_compress_proof, OrderProof, ProofError},
    utxo::utxo_witness_entries,
    ProofInputUtxo,
};

/// Proof inputs for the `pool_settle` circuit: 2-in (order, pool note) / 3-out
/// (recipient payout, pool change, maker receipt), the exact IN2_OUT3 shape,
/// no padding. The private minimum price committed by the order selects either
/// a destination-asset fill or a full source-asset refund. A fill is funded
/// from a pool note locked under the pair's
/// pool_authority PDA; the change returns to the pool with its booked value
/// (the note's data hash) reduced by `max(booked_in - max_order_size, 0)`.
/// `execution_price` is public (the escrow account's stored price); the
/// recipient owner-hash and minimum stay private, re-opened from the composite
/// `OrderIn.DataHash` which the public `OrderInHash` pins.
#[derive(Debug, Clone)]
pub struct PoolSettleProofInputs {
    pub public_input_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    pub execution_price: u64,
    /// The order-input UTXO's own hash -- the escrow account's on-chain
    /// `Escrow.order_utxo_hash`, asserted equal in-circuit to `Hash(order_in)`.
    pub order_in_hash: [u8; 32],
    /// The pair's destination-asset commitment (`DestinationAsset`), bound to
    /// the pool note and the payout.
    pub destination_asset: [u8; 32],
    /// The pool_authority PDA's owner-hash (`PoolAuthorityOwnerHash`), bound to
    /// `PoolIn.Owner` and `PoolChange.Owner`.
    pub pool_authority_owner_hash: [u8; 32],
    /// The pair's immutable `max_order_size`, entering the booked clamp.
    pub max_order_size: u64,
    /// The maker receipt destination (`ReceiptOwnerHash`), fed on-chain from
    /// `Pair.maker_receipt_owner_hash`.
    pub receipt_owner_hash: [u8; 32],
    pub order_amount: u64,
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
    pub order_in: ProofInputUtxo,
    pub pool_in: ProofInputUtxo,
    pub recipient_out: ProofInputUtxo,
    pub pool_change: ProofInputUtxo,
    pub maker_receipt: ProofInputUtxo,
    pub external_data_hash: [u8; 32],
}

impl PoolSettleProofInputs {
    fn witness(&self) -> ffi::WitnessMap {
        let mut map = HashMap::new();
        map.insert(
            "Public_PublicInputHash".to_string(),
            vec![bytes_to_decimal_string(&self.public_input_hash)],
        );
        map.insert(
            "Public_PrivateTxHash".to_string(),
            vec![bytes_to_decimal_string(&self.private_tx_hash)],
        );
        map.insert(
            "Public_ExecutionPrice".to_string(),
            vec![self.execution_price.to_string()],
        );
        map.insert(
            "Public_OrderInHash".to_string(),
            vec![bytes_to_decimal_string(&self.order_in_hash)],
        );
        map.insert(
            "Public_DestinationAsset".to_string(),
            vec![bytes_to_decimal_string(&self.destination_asset)],
        );
        map.insert(
            "Public_PoolAuthorityOwnerHash".to_string(),
            vec![bytes_to_decimal_string(&self.pool_authority_owner_hash)],
        );
        map.insert(
            "Public_MaxOrderSize".to_string(),
            vec![self.max_order_size.to_string()],
        );
        map.insert(
            "Public_ReceiptOwnerHash".to_string(),
            vec![bytes_to_decimal_string(&self.receipt_owner_hash)],
        );
        map.insert(
            "OrderAmount".to_string(),
            vec![self.order_amount.to_string()],
        );
        map.insert(
            "RecipientOwnerHash".to_string(),
            vec![bytes_to_decimal_string(&self.recipient_owner_hash)],
        );
        map.insert("MinPrice".to_string(), vec![self.min_price.to_string()]);
        map.insert(
            "ExternalDataHash".to_string(),
            vec![bytes_to_decimal_string(&self.external_data_hash)],
        );
        for (key, value) in utxo_witness_entries(&self.order_in, "OrderIn")
            .into_iter()
            .chain(utxo_witness_entries(&self.pool_in, "PoolIn"))
            .chain(utxo_witness_entries(&self.recipient_out, "RecipientOut"))
            .chain(utxo_witness_entries(&self.pool_change, "PoolChange"))
            .chain(utxo_witness_entries(&self.maker_receipt, "MakerReceipt"))
        {
            map.insert(key, value);
        }
        map
    }

    pub fn prove(&self) -> Result<OrderProof, ProofError> {
        negate_and_compress_proof(&ffi::prove(CircuitId::PoolSettle, &self.witness())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn sample() -> PoolSettleProofInputs {
        PoolSettleProofInputs {
            public_input_hash: [1; 32],
            private_tx_hash: [2; 32],
            execution_price: 90,
            order_in_hash: [3; 32],
            destination_asset: [4; 32],
            pool_authority_owner_hash: [5; 32],
            max_order_size: 100,
            receipt_owner_hash: [6; 32],
            order_amount: 50,
            recipient_owner_hash: [9; 32],
            min_price: 80,
            order_in: ProofInputUtxo::default(),
            pool_in: ProofInputUtxo::default(),
            recipient_out: ProofInputUtxo::default(),
            pool_change: ProofInputUtxo::default(),
            maker_receipt: ProofInputUtxo::default(),
            external_data_hash: [8; 32],
        }
    }

    #[test]
    fn witness_key_set_matches_circuit_fields() {
        let witness = sample().witness();
        let keys: HashSet<&str> = witness.keys().map(String::as_str).collect();

        let mut expected: Vec<String> = vec![
            "Public_PublicInputHash".to_string(),
            "Public_PrivateTxHash".to_string(),
            "Public_ExecutionPrice".to_string(),
            "Public_OrderInHash".to_string(),
            "Public_DestinationAsset".to_string(),
            "Public_PoolAuthorityOwnerHash".to_string(),
            "Public_MaxOrderSize".to_string(),
            "Public_ReceiptOwnerHash".to_string(),
            "OrderAmount".to_string(),
            "RecipientOwnerHash".to_string(),
            "MinPrice".to_string(),
            "ExternalDataHash".to_string(),
        ];
        for prefix in [
            "OrderIn",
            "PoolIn",
            "RecipientOut",
            "PoolChange",
            "MakerReceipt",
        ] {
            for suffix in [
                "Domain",
                "Owner",
                "Asset",
                "Amount",
                "Blinding",
                "DataHash",
                "RingDataHash",
                "RingProgramID",
            ] {
                expected.push(format!("{prefix}_{suffix}"));
            }
        }

        let expected: HashSet<&str> = expected.iter().map(String::as_str).collect();
        assert_eq!(keys, expected);
    }
}
